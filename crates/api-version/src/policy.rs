//! Deciding which contract a request speaks, and refusing when we cannot.

use std::sync::Arc;

use axum::Json;
use axum::response::{IntoResponse, Response};
use http::{HeaderName, HeaderValue, StatusCode};
use serde_json::json;

use crate::{ApiVersion, TransformRegistry};

/// Bodies larger than this are not rewritten — see [`ApiVersionContext::with_max_body_bytes`].
const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The contract version a caller is bound to when it sends no header.
///
/// Products insert this in their auth layer, from wherever the pin is stored —
/// a column on the API token, on the org, on the installation. Keeping it an
/// extension is what lets this crate know nothing about how a product
/// authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedApiVersion(pub ApiVersion);

/// Everything the negotiation layer needs, cheap to clone.
#[derive(Clone, Debug)]
pub struct ApiVersionContext {
    header: HeaderName,
    current: ApiVersion,
    oldest_supported: ApiVersion,
    default: ApiVersion,
    max_body_bytes: usize,
    registry: Arc<TransformRegistry>,
}

impl ApiVersionContext {
    /// Build a context.
    ///
    /// `header` is deliberately required and has no default. The name belongs
    /// to the product — `x-ferrfleet-api-version`, `x-ferrvault-api-version` —
    /// because `FerrLabs` is both the org and a product, so an org-wide name
    /// would be ambiguous exactly where it matters. A default here would let a
    /// service ship under the wrong name by omission.
    ///
    /// `oldest_supported` is the sunset boundary: anything older is
    /// [`Gone`](StatusCode::GONE) rather than quietly served the wrong shape.
    ///
    /// Callers that send no header and carry no [`PinnedApiVersion`] get
    /// `oldest_supported` as their default — never `current`. A caller that
    /// says nothing is a caller written against whatever shipped when it was
    /// written, and defaulting it to the newest contract would break it the
    /// day a transform lands, which is the failure this crate exists to
    /// prevent.
    pub fn new(
        header: &str,
        current: ApiVersion,
        oldest_supported: ApiVersion,
    ) -> Result<Self, InvalidHeaderName> {
        if oldest_supported > current {
            return Err(InvalidHeaderName::SunsetAfterCurrent);
        }
        let header = HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| InvalidHeaderName::NotAHeaderName)?;
        Ok(Self {
            header,
            current,
            oldest_supported,
            default: oldest_supported,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            registry: Arc::new(TransformRegistry::new()),
        })
    }

    /// Attach the transforms this service knows about.
    ///
    /// An empty registry is a valid, useful state: the header is parsed,
    /// pinned and enforced while there is nothing yet to rewrite.
    #[must_use]
    pub fn with_registry(mut self, registry: TransformRegistry) -> Self {
        self.registry = Arc::new(registry);
        self
    }

    /// Override the version used for callers that send no header and carry no
    /// pin. Must not be newer than `current`.
    #[must_use]
    pub fn with_default(mut self, default: ApiVersion) -> Self {
        debug_assert!(default <= self.current, "default is newer than current");
        self.default = default.min(self.current);
        self
    }

    /// Cap on the body size the layer will buffer in order to rewrite it.
    ///
    /// A body over the cap cannot be transformed. The layer answers `500`
    /// rather than passing the current shape to a client that asked for an
    /// older one: silently serving the wrong contract is the one outcome this
    /// crate must never produce.
    #[must_use]
    pub fn with_max_body_bytes(mut self, max: usize) -> Self {
        self.max_body_bytes = max;
        self
    }

    #[must_use]
    pub fn header(&self) -> &HeaderName {
        &self.header
    }

    #[must_use]
    pub fn current(&self) -> ApiVersion {
        self.current
    }

    #[must_use]
    pub fn oldest_supported(&self) -> ApiVersion {
        self.oldest_supported
    }

    #[must_use]
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    #[must_use]
    pub fn registry(&self) -> &TransformRegistry {
        &self.registry
    }

    /// Which contract this request speaks.
    ///
    /// Header, then [`PinnedApiVersion`], then the configured default.
    pub fn resolve(
        &self,
        headers: &http::HeaderMap,
        pinned: Option<PinnedApiVersion>,
    ) -> Result<ApiVersion, VersionRejection> {
        let Some(raw) = headers.get(&self.header) else {
            return Ok(pinned.map_or(self.default, |PinnedApiVersion(v)| v));
        };
        let raw = raw
            .to_str()
            .map_err(|_| VersionRejection::Malformed(String::new()))?;
        let version: ApiVersion = raw
            .parse()
            .map_err(|_| VersionRejection::Malformed(raw.to_owned()))?;

        if version > self.current {
            return Err(VersionRejection::FromTheFuture {
                requested: version,
                current: self.current,
            });
        }
        if version < self.oldest_supported {
            return Err(VersionRejection::Sunset {
                requested: version,
                oldest_supported: self.oldest_supported,
            });
        }
        Ok(version)
    }
}

/// Why a context could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidHeaderName {
    /// Not a legal HTTP header name.
    NotAHeaderName,
    /// The sunset boundary is newer than the current contract, which would
    /// reject every caller including the newest.
    SunsetAfterCurrent,
}

impl std::fmt::Display for InvalidHeaderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAHeaderName => f.write_str("not a valid HTTP header name"),
            Self::SunsetAfterCurrent => {
                f.write_str("oldest supported version is newer than the current one")
            }
        }
    }
}

impl std::error::Error for InvalidHeaderName {}

/// Why a request's contract version was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRejection {
    /// The header was not a `YYYY-MM-DD` date.
    Malformed(String),
    /// Newer than anything this build serves — typically a package version
    /// sent by mistake, or a client talking to a service that has not been
    /// deployed yet.
    FromTheFuture {
        requested: ApiVersion,
        current: ApiVersion,
    },
    /// Past the sunset window. Answering `410` states that the contract
    /// existed and was withdrawn, which `400` would not.
    Sunset {
        requested: ApiVersion,
        oldest_supported: ApiVersion,
    },
    /// The body could not be rewritten into the requested shape.
    NotTransformable,
}

impl IntoResponse for VersionRejection {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            Self::Malformed(raw) => (
                StatusCode::BAD_REQUEST,
                "invalid_api_version",
                format!("`{raw}` is not an API version; expected a date of the form YYYY-MM-DD"),
            ),
            Self::FromTheFuture { requested, current } => (
                StatusCode::BAD_REQUEST,
                "unknown_api_version",
                format!("API version {requested} is newer than {current}, the latest served here"),
            ),
            Self::Sunset {
                requested,
                oldest_supported,
            } => (
                StatusCode::GONE,
                "sunset_api_version",
                format!(
                    "API version {requested} is no longer served; \
                     the oldest still supported is {oldest_supported}"
                ),
            ),
            Self::NotTransformable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_version_not_applicable",
                "the response could not be rendered in the requested API version".to_owned(),
            ),
        };
        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

/// The resolved version, echoed back so a client can see what it was served.
pub(crate) fn response_header(version: ApiVersion) -> HeaderValue {
    HeaderValue::from_str(&version.to_string())
        .unwrap_or_else(|_| HeaderValue::from_static("unknown"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    fn version(raw: &str) -> ApiVersion {
        raw.parse().unwrap()
    }

    fn context() -> ApiVersionContext {
        ApiVersionContext::new(
            "x-ferrfleet-api-version",
            version("2026-10-01"),
            version("2026-01-01"),
        )
        .unwrap()
    }

    fn headers(raw: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-ferrfleet-api-version", raw.parse().unwrap());
        headers
    }

    #[test]
    fn an_explicit_header_wins() {
        let resolved = context()
            .resolve(
                &headers("2026-05-05"),
                Some(PinnedApiVersion(version("2026-02-02"))),
            )
            .unwrap();
        assert_eq!(resolved, version("2026-05-05"));
    }

    #[test]
    fn without_a_header_the_pin_applies() {
        let resolved = context()
            .resolve(
                &HeaderMap::new(),
                Some(PinnedApiVersion(version("2026-02-02"))),
            )
            .unwrap();
        assert_eq!(resolved, version("2026-02-02"));
    }

    /// The decision the whole design rests on. A caller that says nothing was
    /// written against an older contract, and handing it the newest one would
    /// break it silently the day a transform lands.
    #[test]
    fn an_unpinned_caller_never_defaults_to_current() {
        let ctx = context();
        let resolved = ctx.resolve(&HeaderMap::new(), None).unwrap();
        assert_eq!(resolved, ctx.oldest_supported());
        assert_ne!(resolved, ctx.current());
    }

    #[test]
    fn a_package_version_is_refused_rather_than_guessed() {
        let err = context().resolve(&headers("3.36.0"), None).unwrap_err();
        assert_eq!(err, VersionRejection::Malformed("3.36.0".to_owned()));
    }

    #[test]
    fn a_future_version_is_refused() {
        let err = context().resolve(&headers("2027-01-01"), None).unwrap_err();
        assert!(matches!(err, VersionRejection::FromTheFuture { .. }));
    }

    #[test]
    fn a_sunset_version_is_gone_not_bad_request() {
        let err = context().resolve(&headers("2025-01-01"), None).unwrap_err();
        assert!(matches!(err, VersionRejection::Sunset { .. }));
        assert_eq!(err.into_response().status(), StatusCode::GONE);
    }

    #[test]
    fn the_boundaries_themselves_are_served() {
        let ctx = context();
        assert!(ctx.resolve(&headers("2026-01-01"), None).is_ok());
        assert!(ctx.resolve(&headers("2026-10-01"), None).is_ok());
    }

    #[test]
    fn a_header_name_is_required_to_be_one() {
        assert_eq!(
            ApiVersionContext::new("not a header", version("2026-10-01"), version("2026-01-01"))
                .err(),
            Some(InvalidHeaderName::NotAHeaderName)
        );
    }

    #[test]
    fn a_sunset_newer_than_current_is_refused() {
        assert_eq!(
            ApiVersionContext::new(
                "x-ferrfleet-api-version",
                version("2026-01-01"),
                version("2026-10-01")
            )
            .err(),
            Some(InvalidHeaderName::SunsetAfterCurrent)
        );
    }
}
