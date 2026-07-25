# VALKEY_PASSWORD support — report

## Champ fred utilisé

`fred::types::config::RedisConfig` (fred 9.4.0), source lue directement dans
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/fred-9.4.0/src/types/config.rs` :

```
pub struct RedisConfig {
  ...
  pub username:  Option<String>,   // line 660
  pub password:  Option<String>,   // line 664
  ...
}
```

`connect()` (crates/cache/src/lib.rs) écrit désormais sur ce champ après
`RedisConfig::from_url(...)` :

```rust
if let Some(password) = &config.password {
    cfg.password = Some(password.clone());
}
```

`password` a priorité sur toute credential déjà présente dans l'URL, car cette
écriture se fait *après* `from_url` (qui aurait déjà positionné `cfg.password`
depuis l'URL le cas échéant) et l'écrase donc.

## Portée implémentée

1. `CacheConfig.password: Option<String>` ajouté.
2. `CacheConfig::from_env()` lit `VALKEY_PASSWORD` (vide → `None`, même
   pattern que `VALKEY_CA_CERT`/`VALKEY_POOL_SIZE`).
3. `connect()` : `password` (si `Some`) écrase `cfg.password` après
   `from_url`.
4. Le percent-encoding existant (`percent_encode_userinfo`) est **inchangé** —
   la forme URL-avec-credentials reste supportée en rétro-compatibilité.
5. Doc-comments sur `CacheConfig::password` et `CacheConfig::from_env`
   expliquant que `VALKEY_PASSWORD` est le chemin recommandé et que l'URL ne
   peut structurellement pas représenter un password contenant un `?`/`#` brut
   (le percent-encoding de l'userinfo borne volontairement sa recherche du
   séparateur `@` à gauche du premier `?`/`#` de l'URL — un `?`/`#` dans un
   password non encore encodé est donc indiscernable du début de la
   query/fragment réelle de l'URL).

Tous les sites de construction existants de `CacheConfig { .. }` (3 dans
`lib.rs`, 1 dans `swr.rs`) ont été mis à jour avec `password: None`. Aucun
autre crate du workspace ne construit `CacheConfig` (`grep` sur
`ferrlabs_cache`/`ferrlabs-cache` en dehors de `crates/cache/` : aucun
résultat).

`Cargo.toml` : `version` non touché (reste `0.4.0`, FerrFlow versionne au
merge).

## Preuve TDD

Deux instances `valkey-server` locales montées pour la durée du test (ports
choisis pour ne pas collisionner avec les instances déjà en place sur
6379/6380/6390) :

- port `16382`, `--requirepass 'ab/cd+ef=gh'` — password "normal"
  (percent-encodable), pour le chemin nominal + le test de priorité.
- port `16391`, `--requirepass 'pa?ss#word/x+y=z'` — password contenant un
  `?` et un `#` bruts, le cas que l'URL ne peut pas représenter.

4 nouveaux tests ajoutés dans `crates/cache/src/lib.rs`, tous gate-és par
variables d'env (comme les tests existants), tous exécutés réellement (pas
seulement compilés) :

```
TEST_VALKEY_PASSWORD_URL=redis://127.0.0.1:16382
TEST_VALKEY_PASSWORD=ab/cd+ef=gh
TEST_VALKEY_UNENCODABLE_PASSWORD_URL=redis://127.0.0.1:16391
TEST_VALKEY_UNENCODABLE_PASSWORD=pa?ss#word/x+y=z
TEST_VALKEY_URL_SAFE_PASSWORD_URL=redis://:ab/cd+ef=gh@127.0.0.1:16382
cargo test -p ferrlabs-cache
```

Résultat : **25 passed; 0 failed** (18 tests pré-existants + 4 nouveaux
`VALKEY_PASSWORD` + 3 nouveaux de rédaction `Debug`, cf. section revue), tous
réellement exécutés (aucun "skipping" pour les tests password — vérifié avec
`--nocapture`). `cargo fmt --check` et
`cargo clippy -p ferrlabs-cache --all-targets -- -D warnings` propres.

Preuve que les tests ne "passent pas par hasard" : rejoué
`connects_with_password_supplied_out_of_band` avec un mauvais
`TEST_VALKEY_PASSWORD` → échec réel et attendu :

```
panicked ...: Valkey connect failed: Authentication Error: WRONGPASS invalid
username-password pair or user is disabled.
```

confirmant que `requirepass` est bien actif sur l'instance de test et que le
test positif exerce une vraie authentification AUTH, pas un succès accidentel
sans password.

## Preuve du test #2 (le cœur de la valeur ajoutée)

- `url_with_credentials_cannot_represent_a_password_containing_question_mark_or_hash` :
  construit l'URL brute `redis://:pa?ss#word/x+y=z@127.0.0.1:16391` (exactement
  la forme qu'un template Vault produirait, non pré-encodée) et appelle
  `connect()` avec `password: None`. Résultat : `connect()` échoue
  (`result.is_err()` — dans ce cas concret, `percent_encode_userinfo` borne sa
  recherche du `@` à gauche du premier `?`/`#` trouvé dans l'URL brute ; ce `?`
  apparaît *dans* le password non encore encodé, donc aucun `@` n'est trouvé
  avant lui, l'URL est renvoyée inchangée, et `RedisConfig::from_url` échoue
  sur l'URL malformée qui en résulte — `EmptyHost` ou équivalent). Le test
  passe (l'échec est bien constaté).
- `valkey_password_handles_a_password_containing_question_mark_or_hash` : même
  password brut (`pa?ss#word/x+y=z`), mais fourni via `CacheConfig.password`
  contre une URL sans credentials (`redis://127.0.0.1:16391`) → `connect()`
  réussit, `SET`/`GET` réels passent. Prouve que `VALKEY_PASSWORD` gère
  exactement le cas que l'URL ne peut pas représenter.

Ces deux tests, exécutés côte à côte sur la même instance/le même password,
constituent la preuve a/b demandée : (a) échoue via l'URL, (b) réussit via
`VALKEY_PASSWORD`.

## Revue — finding Important corrigé : rédaction des secrets dans `Debug`

Finding valide et accepté : `CacheConfig` dérivait `Debug` avec un `password:
String` nu → un `tracing::debug!(?config)` ou `{:?}` aurait imprimé le secret
en clair, annulant la raison d'être de `VALKEY_PASSWORD`.

Correction (commit séparé) :

- `#[derive(Debug, Clone)]` → `#[derive(Clone)]` + impl `Debug` manuelle.
- `password` → `Some("<redacted>")` / `None` (jamais la valeur, jamais la
  longueur : `self.password.as_ref().map(|_| "<redacted>")`).
- `url` → passé par un helper `redact_url` : ne garde que schéma + host
  (`redis://127.0.0.1:6379`), supprime l'userinfo (qui porte le password dans
  la forme `redis://:pw@host`) **et** le path/query/fragment.
- Cas pathologique géré : quand le password contient un `?`/`#` brut, la
  frontière de l'userinfo est indécidable ; `redact_url` bascule alors sur
  `<redacted>` complet plutôt que d'imprimer un préfixe du password (sans ce
  garde-fou, `redis://:pa?ss#word@host` aurait affiché `redis://:pa`).
- `pool_size` / `ca_cert_path` laissés en clair (non-secrets), `Clone`
  conservé, doc-comment sur la struct expliquant pourquoi l'impl est manuelle
  ("Do **not** replace it with `#[derive(Debug)]`").

3 tests ajoutés : `debug_redacts_password_and_url_credentials` (password
`supersecret` + URL `redis://:supersecret@host:6379` → output ne contient PAS
`supersecret`, contient `<redacted>`, garde `host:6379` et `pool_size: 6`) ;
`debug_renders_absent_password_as_none` (`password: None` → `password: None`,
URL sans creds et chemin CA conservés) ; `debug_redacts_url_whose_password_
contains_a_raw_question_mark` (aucun fragment du password `pa?ss`/`#word`/
`x+y=z` dans l'output).

**Preuve par mutation** : en re-dérivant temporairement `Debug` (simulation de
la régression), 2 des 3 tests échouent avec exactement la fuite attendue —

```
Debug must not leak the password (from the field or the URL), got:
CacheConfig { url: "redis://:supersecret@host:6379", ..., password: Some("supersecret") }
Debug must not leak any part of an unparseable password (found "pa?ss"), got:
CacheConfig { url: "redis://:pa?ss#word/x+y=z@127.0.0.1:6379", ... }
```

— ce qui prouve que les tests attrapent bien la régression qu'ils visent, et
ne passent pas par construction. Impl réelle restaurée ensuite.

Note : une première version du test #3 assertait `!contains("pa")`, ce qui
échouait à tort — le *nom de champ* `password` contient "pa". Corrigé pour
asserter sur des sous-chaînes distinctives du password.

## Revue — minor corrigé : récit du test négatif

Le doc-comment de `url_with_credentials_cannot_represent_a_password_containing_
question_mark_or_hash` prétendait que le serveur recevait un password
« tronqué » (sous-entendu un aller-retour AUTH / `WRONGPASS`). Vérifié
empiriquement (probe temporaire) : le vrai mode d'échec est **antérieur à tout
appel réseau** —

```
SANITIZED = redis://:pa?ss#word/x+y=z@127.0.0.1:16391   <-- inchangée
FROM_URL ERR: Url Error: EmptyHost
```

`percent_encode_userinfo` ne trouve aucun `@` avant le `?`, sort tôt et renvoie
l'URL **inchangée** (aucun encodage appliqué) ; `RedisConfig::from_url` la
rejette ensuite avec `EmptyHost` (surfacé en `invalid VALKEY_URL`). Le
commentaire décrit désormais ce mode d'échec réel en deux étapes ; l'assertion
`is_err()` était et reste juste.

## Concerns

- `CacheConfig.password` est en clair en mémoire (`String`) : le `Debug` est
  désormais sûr, mais le secret n'est pas zeroizé à la libération. Un
  `secrecy::SecretString` irait plus loin ; hors périmètre ici et cohérent
  avec le reste du crate (`url` porte la même classe de secret).
- `redact_url` protège le `Debug` de `CacheConfig`. Un appelant qui logue
  `config.url` **directement** (`tracing::info!(url = %config.url)`) contourne
  cette protection — le champ reste `pub` et en clair. `VALKEY_PASSWORD` +
  URL sans credentials reste donc le vrai remède ; la rédaction est un
  filet de sécurité.
- Aucun changement de comportement pour les consommateurs actuels
  (`password: None` par défaut si `VALKEY_PASSWORD` absent/vide) — la prod
  utilisant aujourd'hui l'URL-avec-credentials continue de fonctionner à
  l'identique.
- Les instances `valkey-server` de test (ports 16382/16391) ont été arrêtées
  après les tests — elles n'étaient pas des instances mentionnées dans le
  brief (6382/6383 n'étaient en fait pas démarrées sur cette machine au
  moment du travail ; 16382/16391 ont été montées ad hoc comme autorisé par
  le brief "Monte-en d'autres si besoin").
