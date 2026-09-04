//! Signature DKIM des messages sortants.
//!
//! Les relais mutualisés signent peu ou mal : OVH, par exemple, ne couvre que
//! l'en-tête `From`, ce qui laisse le sujet et la date réécrivables sans
//! invalider la signature. Signer dans l'application permet de choisir les
//! en-têtes protégés et de ne plus dépendre de l'activation du fournisseur.
//!
//! ```no_run
//! use ferrlabs_mail::DkimSigner;
//! # use lettre::Message;
//! # fn build() -> Message { unimplemented!() }
//!
//! let signer = DkimSigner::from_env()?;
//! let mut message = build();
//! if let Some(signer) = &signer {
//!     signer.sign(&mut message);
//! }
//! # Ok::<(), ferrlabs_mail::DkimError>(())
//! ```
//!
//! # Publication de la clé
//!
//! La clé publique se publie en TXT sur `<selector>._domainkey.<domain>`, au
//! format `v=DKIM1; k=rsa; p=<base64 de la clé publique DER>`. Plusieurs
//! sélecteurs coexistent sans conflit : celui du fournisseur peut rester en
//! place, un message accepte plusieurs signatures et DMARC se contente d'une
//! seule qui s'aligne.

use std::env;

use lettre::Message;
use lettre::message::dkim::{
    DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningAlgorithm,
    DkimSigningKey,
};
use lettre::message::header::HeaderName;

/// En-têtes couverts par la signature.
///
/// `From` est le seul strictement exigé, mais le laisser seul autorise la
/// réécriture du sujet, de la date et du destinataire sans casser la
/// signature. Les quatre ensemble protègent ce qu'un lecteur voit du message.
///
/// `Message-ID` en est volontairement absent. `MessageBuilder::build` insère
/// `Date` quand elle manque, mais ne génère jamais de `Message-ID` : il faut
/// l'avoir posé soi-même. Or annoncer dans `h=` un en-tête que le message ne
/// porte pas est du null-signing, ce que la RFC 6376 §5.4 définit comme le
/// mécanisme **interdisant** son ajout ultérieur. Le relais qui pose le
/// `Message-ID` manquant — ce que fait à peu près tout MSA — invaliderait donc
/// la signature, produisant exactement le `dkim=fail` que cette crate existe
/// pour éviter.
///
/// Il pourra revenir le jour où un appelant garantit l'en-tête avant de
/// signer.
const SIGNED_HEADERS: [&str; 4] = ["From", "To", "Subject", "Date"];

#[derive(Debug, thiserror::Error)]
pub enum DkimError {
    #[error(
        "la clé privée DKIM doit être au format PKCS#1 (`BEGIN RSA PRIVATE KEY`) ; \
         convertir une clé PKCS#8 avec `openssl rsa -in cle.pem -traditional`"
    )]
    KeyFormat,
    #[error("configuration DKIM incomplète : {0} est absent alors que les autres sont définis")]
    Incomplete(&'static str),
}

/// Signataire construit une fois au démarrage et réutilisé pour chaque message.
///
/// Volontairement sans `Debug` : la structure détient la clé privée, et une
/// clé qui peut atteindre un log est une clé à renouveler.
pub struct DkimSigner {
    config: DkimConfig,
}

impl DkimSigner {
    /// Lit `MAIL_DKIM_PRIVATE_KEY`, `MAIL_DKIM_SELECTOR` et `MAIL_DKIM_DOMAIN`.
    ///
    /// Renvoie `Ok(None)` quand aucune des trois n'est définie : une
    /// application qui n'a pas encore de clé continue d'envoyer sans signer,
    /// ce qui vaut mieux que de refuser de démarrer. En revanche une
    /// configuration partielle est une erreur, parce qu'elle traduit presque
    /// toujours une variable oubliée au déploiement et se solderait sinon par
    /// des messages non signés sans que personne ne le remarque.
    pub fn from_env() -> Result<Option<Self>, DkimError> {
        let key = env::var("MAIL_DKIM_PRIVATE_KEY")
            .ok()
            .filter(|v| !v.is_empty());
        let selector = env::var("MAIL_DKIM_SELECTOR")
            .ok()
            .filter(|v| !v.is_empty());
        let domain = env::var("MAIL_DKIM_DOMAIN").ok().filter(|v| !v.is_empty());

        match (key, selector, domain) {
            (None, None, None) => {
                tracing::info!("DKIM non configuré, les messages partiront non signés");
                Ok(None)
            }
            (Some(key), Some(selector), Some(domain)) => {
                Self::new(&key, selector, domain).map(Some)
            }
            (key, selector, _) => Err(DkimError::Incomplete(if key.is_none() {
                "MAIL_DKIM_PRIVATE_KEY"
            } else if selector.is_none() {
                "MAIL_DKIM_SELECTOR"
            } else {
                "MAIL_DKIM_DOMAIN"
            })),
        }
    }

    /// `key` est une clé RSA privée au format PEM PKCS#1.
    pub fn new(key: &str, selector: String, domain: String) -> Result<Self, DkimError> {
        let key = DkimSigningKey::new(key, DkimSigningAlgorithm::Rsa)
            .map_err(|_| DkimError::KeyFormat)?;

        let headers = SIGNED_HEADERS
            .iter()
            .map(|name| HeaderName::new_from_ascii_str(name))
            .collect();

        // `relaxed/relaxed`, jamais `DkimConfig::default_config`, qui applique
        // `simple` aux en-têtes : dans ce mode le moindre repli de ligne
        // réappliqué par un relais invalide la signature, et un `dkim=fail`
        // est plus dommageable qu'une absence de signature. Vérifié contre le
        // relais mutualisé d'OVH : `simple` échoue, `relaxed` passe.
        let canonicalization = DkimCanonicalization {
            header: DkimCanonicalizationType::Relaxed,
            body: DkimCanonicalizationType::Relaxed,
        };

        Ok(Self {
            config: DkimConfig::new(selector, domain, key, headers, canonicalization),
        })
    }

    /// Ajoute l'en-tête `DKIM-Signature` au message.
    ///
    /// À appeler en dernier, une fois tous les en-têtes signés posés : signer
    /// puis modifier `Subject` ou `Date` produirait une signature invalide.
    pub fn sign(&self, message: &mut Message) {
        message.sign(&self.config);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clé de test, sans valeur : générée pour ce fichier et publiée avec lui.
    const TEST_KEY: &str = include_str!("../tests/testing.key");

    fn message() -> Message {
        Message::builder()
            .from("Expediteur <expediteur@example.com>".parse().unwrap())
            .to("destinataire@example.org".parse().unwrap())
            .subject("Sujet")
            .body(String::from("Corps du message.\n"))
            .unwrap()
    }

    fn signed_header(message: &Message) -> String {
        let raw = String::from_utf8(message.formatted()).unwrap();
        raw.lines()
            .skip_while(|line| !line.starts_with("DKIM-Signature:"))
            .take_while(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn signs_with_relaxed_canonicalization() {
        let signer = DkimSigner::new(TEST_KEY, "test".into(), "example.com".into()).unwrap();
        let mut message = message();
        signer.sign(&mut message);

        let header = signed_header(&message);
        assert!(header.contains("c=relaxed/relaxed"), "en-tête : {header}");
    }

    /// Chaque en-tête déclaré dans `h=` doit exister DANS le message.
    ///
    /// C'est la vérification qui manquait : `covers_every_declared_header` lit
    /// la liste annoncée sans regarder le message, donc il passait sur un
    /// `Message-ID` que `lettre` ne génère pas. Annoncer un en-tête absent est
    /// du null-signing, et la RFC 6376 §5.4 en fait le mécanisme interdisant
    /// son ajout ultérieur : le relais qui le pose casse la signature.
    #[test]
    fn chaque_entete_declare_existe_dans_le_message() {
        let message = message();
        let brut = String::from_utf8(message.formatted())
            .unwrap()
            .to_lowercase();
        for name in SIGNED_HEADERS {
            assert!(
                brut.contains(&format!("\n{}:", name.to_lowercase()))
                    || brut.starts_with(&format!("{}:", name.to_lowercase())),
                "`{name}` est signé mais absent du message : signature invalidée \
                 dès qu'un relais l'ajoutera"
            );
        }
    }

    #[test]
    fn covers_every_declared_header() {
        let signer = DkimSigner::new(TEST_KEY, "test".into(), "example.com".into()).unwrap();
        let mut message = message();
        signer.sign(&mut message);

        let header = signed_header(&message).to_lowercase();
        for name in SIGNED_HEADERS {
            assert!(
                header.contains(&name.to_lowercase()),
                "{name} absent de la liste signée : {header}"
            );
        }
    }

    #[test]
    fn announces_the_selector_and_the_domain() {
        let signer = DkimSigner::new(TEST_KEY, "sel1".into(), "example.com".into()).unwrap();
        let mut message = message();
        signer.sign(&mut message);

        let header = signed_header(&message);
        assert!(header.contains("s=sel1"), "en-tête : {header}");
        assert!(header.contains("d=example.com"), "en-tête : {header}");
    }

    #[test]
    fn rejects_a_pkcs8_key_with_a_usable_message() {
        let pkcs8 = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n";
        let error = DkimSigner::new(pkcs8, "test".into(), "example.com".into())
            .err()
            .expect("une clé PKCS#8 doit être refusée");
        assert!(matches!(error, DkimError::KeyFormat));
        assert!(error.to_string().contains("traditional"));
    }
}
