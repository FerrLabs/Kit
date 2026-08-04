#![forbid(unsafe_code)]
//! Date-based API contract versioning, with transforms that render older
//! shapes to older clients.
//!
//! # The problem
//!
//! `/api/v1` written into every route, and a `v1` that never moves, is not
//! versioning — it is a prefix. It holds only while the sole client of an API
//! is the first-party SPA deployed alongside it. It stops holding the moment
//! there is a client that cannot be updated in step: a self-hosted install, an
//! API token in someone else's script, an MCP server.
//!
//! # Why a date rather than a number
//!
//! A number looks like the package version, and the two must never coincide —
//! the `api` crate ships ten times without the contract moving. A number also
//! turns editorial: incrementing feels expensive, five changes get bundled
//! into one `v2`, and the transform chain works best with many small steps.
//! A date is cheap to mint, self-describing, and impossible to confuse with
//! `3.36.0`.
//!
//! # Why not `/v2`
//!
//! A second router has to carry every later addition twice, forever. A
//! transform is written once, at the moment of the change, and then left
//! alone.
//!
//! # Shape of it
//!
//! - [`ApiVersion`] — a date, totally ordered.
//! - [`ApiVersionContext`] — the header name, the current contract, the sunset
//!   boundary, the transforms.
//! - [`PinnedApiVersion`] — the version a caller is bound to when it sends no
//!   header, inserted by the product from wherever it stores the pin.
//! - [`Transform`] — one change, and how to undo it.
//! - [`negotiate`] — the middleware.
//!
//! ```ignore
//! use axum::middleware::from_fn_with_state;
//! use ferrlabs_api_version::{ApiVersion, ApiVersionContext, TransformRegistry, negotiate};
//!
//! const CURRENT: ApiVersion = match ApiVersion::from_ymd(2026, 10, 1) {
//!     Some(v) => v,
//!     None => panic!("invalid contract version"),
//! };
//! const SUNSET: ApiVersion = match ApiVersion::from_ymd(2026, 1, 1) {
//!     Some(v) => v,
//!     None => panic!("invalid contract version"),
//! };
//!
//! let ctx = ApiVersionContext::new("x-ferrfleet-api-version", CURRENT, SUNSET)?
//!     .with_registry(TransformRegistry::new().with(RenamedNameToLabel));
//!
//! let router = router.layer(from_fn_with_state(ctx, negotiate));
//! # Ok::<(), ferrlabs_api_version::InvalidHeaderName>(())
//! ```
//!
//! The header name is per-product and has no default. `FerrLabs` is both the
//! org and a product, so an org-wide name would be ambiguous exactly where it
//! matters.
//!
//! An empty registry is a valid state, and a deliberate first step: the header
//! is parsed, pinned and enforced while there is nothing yet to rewrite.
//!
//! # What this does not do
//!
//! **Streams.** A transform rewrites a whole document. Server-sent events and
//! other non-JSON payloads pass through untouched, and the routes serving them
//! are not versioned. Decide that explicitly rather than discover it.
//!
//! **Semantic changes.** This protects the *shape* of an exchange, never its
//! meaning. A migration that empties a table passes straight through: the
//! response is still a well-formed list, it is simply empty, and no transform
//! fires because nothing about the contract changed. That class of breakage
//! belongs to expand/contract discipline on migrations — never remove, in one
//! release, what the currently deployed client still reads. The two concerns
//! are disjoint, and this crate settles only one of them.
//!
//! **Sunsetting itself.** Transforms accumulate. [`ApiVersionContext`] enforces
//! a floor and answers [`410 Gone`](http::StatusCode::GONE) below it, but
//! choosing when to raise that floor, and deleting the transforms it strands,
//! stays a decision.

mod layer;
mod policy;
mod transform;
mod version;

pub use layer::{SERVED_HEADER, negotiate};
pub use policy::{ApiVersionContext, InvalidHeaderName, PinnedApiVersion, VersionRejection};
pub use transform::{Transform, TransformRegistry};
pub use version::{ApiVersion, ParseApiVersionError};
