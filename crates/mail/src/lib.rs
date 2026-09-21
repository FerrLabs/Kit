//! DKIM signing for outgoing mail.
//!
//! Shared relays sign poorly or not at all: OVH, for instance, only covers the
//! `From` header, which leaves the subject and the date rewritable without
//! breaking the signature. Signing in the application lets you choose which
//! headers are protected, and stops depending on the provider enabling it.
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
//! # Publishing the key
//!
//! The public key goes in a TXT record at `<selector>._domainkey.<domain>`, as
//! `v=DKIM1; k=rsa; p=<base64 of the DER public key>`. Several selectors
//! coexist without conflict: the provider's own can stay in place, a message
//! accepts several signatures, and DMARC only needs one that aligns.

use std::env;

use lettre::Message;
use lettre::message::dkim::{
    DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningAlgorithm,
    DkimSigningKey,
};
use lettre::message::header::HeaderName;

/// Headers covered by the signature.
///
/// `From` is the only one strictly required, but signing it alone lets the
/// subject, the date and the recipient be rewritten without breaking the
/// signature. The four together protect what a reader actually sees.
///
/// `Message-ID` is left out on purpose. `MessageBuilder::build` inserts `Date`
/// when it is missing but never generates a `Message-ID`, so the caller has to
/// set it. Declaring in `h=` a header the message does not carry is
/// null-signing, which RFC 6376 section 5.4 defines as the mechanism that
/// **forbids** adding it later. The relay that fills in the missing
/// `Message-ID`, as nearly every MSA does, would then break the signature and
/// produce exactly the `dkim=fail` this crate exists to avoid.
///
/// It can come back once a caller guarantees the header before signing.
const SIGNED_HEADERS: [&str; 4] = ["From", "To", "Subject", "Date"];

#[derive(Debug, thiserror::Error)]
pub enum DkimError {
    #[error(
        "the DKIM private key must be PKCS#1 (`BEGIN RSA PRIVATE KEY`); \
         convert a PKCS#8 key with `openssl rsa -in key.pem -traditional`"
    )]
    KeyFormat,
    #[error("incomplete DKIM configuration: {0} is missing while the others are set")]
    Incomplete(&'static str),
}

/// Signer built once at startup and reused for every message.
///
/// Deliberately not `Debug`: it holds the private key, and a key that can reach
/// a log is a key that has to be rotated.
pub struct DkimSigner {
    config: DkimConfig,
}

impl DkimSigner {
    /// Reads `MAIL_DKIM_PRIVATE_KEY`, `MAIL_DKIM_SELECTOR` and `MAIL_DKIM_DOMAIN`.
    ///
    /// Returns `Ok(None)` when none of the three is set: an application that
    /// has no key yet keeps sending unsigned, which beats refusing to start. A
    /// partial configuration is an error, because it almost always means a
    /// variable forgotten at deploy time, and would otherwise end in unsigned
    /// mail that nobody notices.
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
                tracing::info!("DKIM not configured, messages will be sent unsigned");
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

    /// `key` is an RSA private key, PEM-encoded PKCS#1.
    pub fn new(key: &str, selector: String, domain: String) -> Result<Self, DkimError> {
        let key = DkimSigningKey::new(key, DkimSigningAlgorithm::Rsa)
            .map_err(|_| DkimError::KeyFormat)?;

        let headers = SIGNED_HEADERS
            .iter()
            .map(|name| HeaderName::new_from_ascii_str(name))
            .collect();

        // `relaxed/relaxed`, never `DkimConfig::default_config`, which applies
        // `simple` to headers: in that mode any line refolding a relay does
        // breaks the signature, and a `dkim=fail` does more harm than no
        // signature at all. Checked against OVH's shared relay: `simple`
        // fails, `relaxed` passes.
        let canonicalization = DkimCanonicalization {
            header: DkimCanonicalizationType::Relaxed,
            body: DkimCanonicalizationType::Relaxed,
        };

        Ok(Self {
            config: DkimConfig::new(selector, domain, key, headers, canonicalization),
        })
    }

    /// Adds the `DKIM-Signature` header to the message.
    ///
    /// Call it last, once every signed header is set: signing and then changing
    /// `Subject` or `Date` produces an invalid signature.
    pub fn sign(&self, message: &mut Message) {
        message.sign(&self.config);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Throwaway test key, generated for this file and published with it.
    const TEST_KEY: &str = include_str!("../tests/testing.key");

    fn message() -> Message {
        Message::builder()
            .from("Sender <sender@example.com>".parse().unwrap())
            .to("recipient@example.org".parse().unwrap())
            .subject("Subject")
            .body(String::from("Message body.\n"))
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
        assert!(header.contains("c=relaxed/relaxed"), "header: {header}");
    }

    /// Every header declared in `h=` must exist IN the message.
    ///
    /// This is the check that was missing: `covers_every_declared_header` reads
    /// the declared list without looking at the message, so it passed on a
    /// `Message-ID` that `lettre` never generates. Declaring an absent header is
    /// null-signing, and RFC 6376 section 5.4 makes it the mechanism that
    /// forbids adding it later: the relay that sets it breaks the signature.
    #[test]
    fn every_declared_header_exists_in_the_message() {
        let message = message();
        let raw = String::from_utf8(message.formatted())
            .unwrap()
            .to_lowercase();
        for name in SIGNED_HEADERS {
            assert!(
                raw.contains(&format!("\n{}:", name.to_lowercase()))
                    || raw.starts_with(&format!("{}:", name.to_lowercase())),
                "`{name}` is signed but missing from the message: the signature \
                 breaks as soon as a relay adds it"
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
                "{name} missing from the signed list: {header}"
            );
        }
    }

    #[test]
    fn announces_the_selector_and_the_domain() {
        let signer = DkimSigner::new(TEST_KEY, "sel1".into(), "example.com".into()).unwrap();
        let mut message = message();
        signer.sign(&mut message);

        let header = signed_header(&message);
        assert!(header.contains("s=sel1"), "header: {header}");
        assert!(header.contains("d=example.com"), "header: {header}");
    }

    #[test]
    fn rejects_a_pkcs8_key_with_a_usable_message() {
        let pkcs8 = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n";
        let error = DkimSigner::new(pkcs8, "test".into(), "example.com".into())
            .err()
            .expect("a PKCS#8 key must be rejected");
        assert!(matches!(error, DkimError::KeyFormat));
        assert!(error.to_string().contains("traditional"));
    }
}
