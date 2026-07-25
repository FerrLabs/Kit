# Task B1 — Rapport d'implémentation

## Résumé

Implémenté le helper SWR `Swr::get_or_load` dans `crates/cache/src/swr.rs`, couvrant
uniquement les chemins **frais**, **miss** et **bypass** (portée B1). La branche
« stale » recharge inline pour l'instant, avec un commentaire explicite renvoyant à
la Task B2 (`tokio::spawn` + single-flight à venir, hors scope ici).

## Fichiers modifiés/créés

- `crates/cache/src/swr.rs` (nouveau) — `Envelope<T>`, `now_ms()`, `Swr<'a>`,
  `Swr::store`, `Swr::get_or_load`, + module `#[cfg(test)]` avec les 2 tests du brief.
- `crates/cache/src/lib.rs` — ajout de `mod swr; pub use swr::Swr;` après les imports.
- `crates/cache/Cargo.toml` — ajout de `serde` (feature `derive`), `serde_json`,
  `tokio` en `[dependencies]`, et `tokio` en `[dev-dependencies]`. **Champ `version`
  non touché** (reste `0.2.0`), conformément à la contrainte FerrFlow.
- `Cargo.lock` — mis à jour automatiquement par `cargo build`/`cargo test`.

## TDD — preuve RED puis GREEN

### RED (Step 2 → Step 3, avant implémentation)

Commande :
```
cd /home/bryan/kit && TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache
```
Sortie (extrait) — le module de test existait déjà (référence `Swr`), mais
`swr::Swr` n'était pas encore défini :
```
error[E0432]: unresolved import `swr::Swr`
  --> crates/cache/src/lib.rs:12:9
   |
12 | pub use swr::Swr;
   |         ^^^^^^^^ no `Swr` in `swr`

error: could not compile `ferrlabs-cache` (lib) due to 1 previous error
```
→ RED confirmé (échec de compilation, pas juste d'assertion, car `Swr` était
strictement absent à ce stade).

### GREEN (après Step 3, implémentation complète)

Commande :
```
cd /home/bryan/kit && TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache
```
Sortie :
```
running 2 tests
test swr::tests::bypass_forces_reload ... ok
test swr::tests::miss_then_fresh_hit_calls_loader_once ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```
Valkey local utilisé : `redis://127.0.0.1:6379` (valkey-server déjà actif sur la
machine, sans password — vérifié par un test TCP direct avant de lancer les tests).
Les deux tests ont réellement tourné contre Valkey (pas de skip) : `miss_then_fresh_hit_calls_loader_once`
prouve que le loader n'est appelé qu'une fois sur un miss suivi d'un hit frais ;
`bypass_forces_reload` prouve que `bypass = true` force un second appel au loader
malgré une entrée déjà en cache.

Vérification complémentaire du skip propre sans `TEST_VALKEY_URL` :
```
cd /home/bryan/kit && cargo test -p ferrlabs-cache
```
→ `2 passed` également (les tests retournent early via `let Some(pool) = pool().await else { return; }`,
donc ils "passent" trivialement sans jamais toucher le réseau — comportement attendu du brief).

### Clippy

```
cd /home/bryan/kit && cargo clippy -p ferrlabs-cache --all-targets -- -D warnings
```
Le code verbatim du brief échouait initialement sur 2 lints `clippy::cast_possible_truncation`
(cast `u128 as u64` dans `now_ms()`, cast `u128 as i64` pour `px`). J'ai ajouté deux
`#[allow(clippy::cast_possible_truncation)]` **ciblés, avec commentaire de justification**
juste au-dessus de chaque cast (pas de allow global) :
- `now_ms()` : un timestamp ms ne dépasse `u64::MAX` que dans ~584 millions d'années.
- `Swr::store` (px) : `hard_ttl` est une durée de config raisonnable (secondes-heures),
  très loin de `i64::MAX` ms.

Après ce correctif : `Finished` sans warning, exit clean.

### cargo fmt

`cargo fmt -p ferrlabs-cache -- --check` a signalé des différences de style pur
(retours à la ligne, ordre `use std::sync::Arc` / `atomic`, `Envelope { .. }` multi-lignes,
etc.) — aucune logique modifiée. Appliqué via `cargo fmt -p ferrlabs-cache`, puis
re-vérifié tests + clippy : toujours GREEN et propre après formatage.

## Auto-revue

- **Portée B1 respectée** : pas de `tokio::spawn`, pas de single-flight, pas de
  crate `futures` ajouté. La branche stale recharge inline avec commentaire
  `// stale : géré en Task B2. Pour l'instant, recharge inline.`
- **Dégradation gracieuse** : une erreur Valkey sur le GET tombe en `loader().await`
  direct (log `tracing::warn!`) plutôt que de propager une erreur bloquante côté
  appelant — cohérent avec l'esprit "cache best-effort" du crate existant (`connect`
  logue déjà via `tracing`).
- **`version` de `Cargo.toml` non touché** (reste `0.2.0`), seules des dépendances
  ajoutées — vérifié explicitement après le commit.
- **Pas de secrets** committés ; `.superpowers-briefs/` volontairement laissé
  untracked (matériel de tâche, hors périmètre du diff de code).
- Le hook pre-commit a fonctionné sans erreur corepack/pnpm cette fois — pas eu besoin
  de `--no-verify`.

## Concerns

1. **`cargo build --workspace` a timeout (2 min)** lors d'une vérification globale
   post-commit — vraisemblablement dû à la taille du workspace complet (première
   compilation froide de nombreux crates), pas lié à `ferrlabs-cache` : le crate
   cible compile et passe ses tests/clippy en quelques secondes de façon isolée.
   À re-vérifier en CI si un doute subsiste sur une régression ailleurs dans le
   workspace (peu probable, aucun autre fichier touché).
2. **`#[allow(clippy::cast_possible_truncation)]`** ajoutés (non présents dans le
   snippet verbatim du brief) pour satisfaire `-D warnings` — changement mineur
   mais réel par rapport au texte du brief ; documenté ci-dessus avec justification
   inline dans le code.
3. **Single-flight / concurrence** : en B1, deux requêtes concurrentes sur un miss
   déclenchent chacune leur propre `loader()` (pas de verrouillage) — comportement
   volontaire et documenté comme héritage explicite à traiter en B2 (`lock_ttl` est
   déjà présent dans la struct mais pas encore utilisé en B1).

## Commandes de vérification (résumé)

```bash
cd /home/bryan/kit
TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache   # 2 passed
cargo clippy -p ferrlabs-cache --all-targets -- -D warnings           # clean
cargo fmt -p ferrlabs-cache                                           # appliqué
git log -1 --stat                                                     # ed8cb4c
```
