//! One contract change, written once and never revisited.

use std::sync::Arc;

use http::Method;
use serde_json::Value;

use crate::ApiVersion;

/// A single change to the contract, and how to undo it for older clients.
///
/// A transform is tagged with the version *at which the change landed*, and it
/// applies to every client pinned strictly before that. It is written at the
/// moment of the change and then left alone — that permanence is what makes
/// this cheaper than a duplicated `/v2` router, where every later addition has
/// to be carried in both.
///
/// Both directions describe the same edge of the timeline:
///
/// - [`downgrade_response`](Transform::downgrade_response) rewrites a body in
///   the shape *at or after* this version into the shape *before* it.
/// - [`upgrade_request`](Transform::upgrade_request) does the reverse for
///   incoming bodies.
///
/// Most changes only need the first: a field added to a response has to be
/// removed for old clients, while old clients simply never send it.
pub trait Transform: Send + Sync + 'static {
    /// The contract version at which this change landed.
    fn version(&self) -> ApiVersion;

    /// Whether this change touches the given route.
    ///
    /// `route` is the matched path template — `/api/v1/agents/{id}` — not the
    /// concrete URI, so a transform does not have to pattern-match ids.
    fn applies_to(&self, route: &str, method: &Method) -> bool;

    /// Rewrite a response body backwards across this change.
    fn downgrade_response(&self, body: &mut Value);

    /// Rewrite a request body forwards across this change.
    ///
    /// Defaults to leaving the body alone, which is correct whenever the
    /// change only affected responses.
    fn upgrade_request(&self, body: &mut Value) {
        let _ = body;
    }
}

/// Every transform a service knows about, kept in chronological order.
#[derive(Clone, Default)]
pub struct TransformRegistry {
    // Ascending by version. Both directions of the chain are derived from this
    // one ordering rather than stored twice, so they cannot disagree.
    transforms: Vec<Arc<dyn Transform>>,
}

impl TransformRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a change. Order of registration does not matter.
    #[must_use]
    pub fn with(mut self, transform: impl Transform) -> Self {
        self.transforms.push(Arc::new(transform));
        self.transforms.sort_by_key(|t| t.version());
        self
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.transforms.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }

    /// The oldest version any registered transform can reach back to.
    ///
    /// `None` for an empty registry, which serves exactly one shape.
    #[must_use]
    pub fn oldest_change(&self) -> Option<ApiVersion> {
        self.transforms.first().map(|t| t.version())
    }

    /// Walk a response body from the current shape back to `pinned`.
    ///
    /// Newest change first: each step undoes one edge of the timeline, so
    /// applying them out of order would feed a transform a shape it was never
    /// written against.
    pub fn downgrade_response(
        &self,
        pinned: ApiVersion,
        route: &str,
        method: &Method,
        body: &mut Value,
    ) {
        for transform in self.transforms.iter().rev() {
            if transform.version() > pinned && transform.applies_to(route, method) {
                transform.downgrade_response(body);
            }
        }
    }

    /// Walk a request body from `pinned` forwards to the current shape.
    pub fn upgrade_request(
        &self,
        pinned: ApiVersion,
        route: &str,
        method: &Method,
        body: &mut Value,
    ) {
        for transform in &self.transforms {
            if transform.version() > pinned && transform.applies_to(route, method) {
                transform.upgrade_request(body);
            }
        }
    }

    /// Whether anything at all would be rewritten.
    ///
    /// Lets the layer skip buffering a body it would hand back unchanged.
    #[must_use]
    pub fn touches(&self, pinned: ApiVersion, route: &str, method: &Method) -> bool {
        self.transforms
            .iter()
            .any(|t| t.version() > pinned && t.applies_to(route, method))
    }
}

impl std::fmt::Debug for TransformRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransformRegistry")
            .field("transforms", &self.transforms.len())
            .field("oldest_change", &self.oldest_change())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn version(raw: &str) -> ApiVersion {
        raw.parse().unwrap()
    }

    /// Appends a marker on the way down and strips one on the way up, so a
    /// test can read the order the chain ran in straight off the body.
    struct Marker {
        at: ApiVersion,
        tag: &'static str,
        route: &'static str,
    }

    impl Transform for Marker {
        fn version(&self) -> ApiVersion {
            self.at
        }
        fn applies_to(&self, route: &str, _method: &Method) -> bool {
            route == self.route
        }
        fn downgrade_response(&self, body: &mut Value) {
            let trail = body["trail"].as_str().unwrap_or_default();
            body["trail"] = json!(format!("{trail}{}", self.tag));
        }
        fn upgrade_request(&self, body: &mut Value) {
            let trail = body["trail"].as_str().unwrap_or_default();
            body["trail"] = json!(format!("{trail}{}", self.tag));
        }
    }

    fn registry() -> TransformRegistry {
        // Deliberately registered out of order: the registry sorts.
        TransformRegistry::new()
            .with(Marker {
                at: version("2026-09-01"),
                tag: "b",
                route: "/agents",
            })
            .with(Marker {
                at: version("2026-08-01"),
                tag: "a",
                route: "/agents",
            })
            .with(Marker {
                at: version("2026-10-01"),
                tag: "c",
                route: "/agents",
            })
    }

    #[test]
    fn responses_walk_backwards_newest_first() {
        let mut body = json!({});
        registry().downgrade_response(version("2026-07-01"), "/agents", &Method::GET, &mut body);
        assert_eq!(body["trail"], "cba");
    }

    #[test]
    fn requests_walk_forwards_oldest_first() {
        let mut body = json!({});
        registry().upgrade_request(version("2026-07-01"), "/agents", &Method::GET, &mut body);
        assert_eq!(body["trail"], "abc");
    }

    /// The whole point of pinning: a client that already speaks a later shape
    /// must not have earlier changes undone for it.
    #[test]
    fn only_changes_newer_than_the_pin_apply() {
        let mut body = json!({});
        registry().downgrade_response(version("2026-09-01"), "/agents", &Method::GET, &mut body);
        assert_eq!(body["trail"], "c");
    }

    #[test]
    fn a_client_at_the_latest_change_is_untouched() {
        let mut body = json!({});
        registry().downgrade_response(version("2026-10-01"), "/agents", &Method::GET, &mut body);
        assert!(body.get("trail").is_none());
        assert!(!registry().touches(version("2026-10-01"), "/agents", &Method::GET));
    }

    #[test]
    fn transforms_skip_routes_they_do_not_claim() {
        let mut body = json!({});
        registry().downgrade_response(version("2026-07-01"), "/runs", &Method::GET, &mut body);
        assert!(body.get("trail").is_none());
        assert!(!registry().touches(version("2026-07-01"), "/runs", &Method::GET));
    }

    #[test]
    fn an_empty_registry_serves_one_shape() {
        let registry = TransformRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.oldest_change(), None);
        assert!(!registry.touches(version("2020-01-01"), "/agents", &Method::GET));
    }

    #[test]
    fn registration_order_does_not_affect_the_chain() {
        let reversed = TransformRegistry::new()
            .with(Marker {
                at: version("2026-10-01"),
                tag: "c",
                route: "/agents",
            })
            .with(Marker {
                at: version("2026-09-01"),
                tag: "b",
                route: "/agents",
            })
            .with(Marker {
                at: version("2026-08-01"),
                tag: "a",
                route: "/agents",
            });
        let mut body = json!({});
        reversed.downgrade_response(version("2026-07-01"), "/agents", &Method::GET, &mut body);
        assert_eq!(body["trail"], "cba");
    }
}
