#![forbid(unsafe_code)]
//! GitHub App authentication.
//!
//! Two concerns a product must handle before it can act on a customer's
//! repositories.
//!
//! **Minting tokens.** [`GithubAppAuth`] signs the App JWT and exchanges it for
//! per-installation access tokens, cached until shortly before they expire.
//!
//! **Proving ownership.** [`GithubOauth`] answers whether the human asking to
//! attach an installation actually controls it. A `FerrLabs` session proves
//! which org the caller acts for and says nothing about GitHub; the missing
//! half is GitHub vouching for the user. Without it, any authenticated user of
//! any org could attach any unclaimed installation and start receiving another
//! account's events under their own tenant.
//!
//! The App JWT is deliberately *not* the instrument for that second question:
//! it can read every installation, so it can confirm one exists but never that
//! the caller owns it. Reaching for it there would look like verification and
//! check nothing.

mod app;
mod ownership;

pub use app::GithubAppAuth;
pub use ownership::{GithubOauth, owns_installation};

/// Why a GitHub operation failed.
///
/// Every variant is a failure to *establish* something, never a denial. A
/// caller deciding whether to grant access must treat an error and a `false`
/// identically.
#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    /// The configured App private key is not a usable RSA PEM.
    #[error("the GitHub App private key is not a valid RSA PEM")]
    PrivateKey(#[source] jsonwebtoken::errors::Error),
    /// Signing the App JWT failed.
    #[error("signing the GitHub App JWT failed")]
    JwtSigning(#[source] jsonwebtoken::errors::Error),
    /// The system clock is before the unix epoch, so no `iat` can be built.
    #[error("the system clock is before the unix epoch")]
    Clock,
    /// A request to GitHub failed, or returned a non-success status.
    #[error("{context}")]
    Http {
        context: &'static str,
        #[source]
        source: reqwest::Error,
    },
    /// The OAuth code could not be exchanged for a user token.
    #[error("exchanging the GitHub OAuth code")]
    Exchange(#[source] ferrlabs_oauth::OAuthError),
}

impl GithubError {
    pub(crate) fn http(context: &'static str) -> impl FnOnce(reqwest::Error) -> Self {
        move |source| Self::Http { context, source }
    }
}
