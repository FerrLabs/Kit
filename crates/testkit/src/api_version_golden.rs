//! Golden tests for [`ferrlabs_api_version`] transform chains.
//!
//! A [`TransformRegistry`] is exercised by construction in its own unit
//! tests, but nothing there catches a chain that has quietly drifted from
//! what a product actually serves: a transform edited for one route that
//! silently stops firing for another, a field renamed twice that round-trips
//! to the wrong spelling, an `applies_to` narrowed by an unrelated change.
//! The issue that shipped this crate called that suite "indissociable" from
//! the mechanism — without it, a working `negotiate` layer is a false
//! assurance, since the layer only proves the *plumbing* runs, never that the
//! *shapes* it produces are still the ones a pinned client expects.
//!
//! [`assert_golden_responses`] renders, for every version a product still
//! serves, the downgraded shape of each route and compares it against a
//! fixture checked into the repo. A mismatch fails the test with both
//! shapes inline; a missing fixture tells you to run with `UPDATE_GOLDEN=1`
//! rather than guess.
//!
//! Transformations and the `CURRENT`/`oldest_supported` versions stay with
//! each product — this harness only needs a [`TransformRegistry`], the
//! versions to check, and one current-shape sample per route.
//!
//! ```no_run
//! use ferrlabs_api_version::{ApiVersion, Transform, TransformRegistry};
//! use ferrlabs_testkit::api_version_golden::{GoldenCase, assert_golden_responses};
//! use http::Method;
//! use serde_json::json;
//!
//! # struct RenamedNameToLabel;
//! # impl Transform for RenamedNameToLabel {
//! #     fn version(&self) -> ApiVersion { "2026-09-01".parse().unwrap() }
//! #     fn applies_to(&self, route: &str, _: &Method) -> bool { route == "/agents/{id}" }
//! #     fn downgrade_response(&self, body: &mut serde_json::Value) {}
//! # }
//! let registry = TransformRegistry::new().with(RenamedNameToLabel);
//!
//! let versions: Vec<ApiVersion> = ["2026-01-01", "2026-09-01", "2026-10-01"]
//!     .map(|d| d.parse().unwrap())
//!     .to_vec();
//!
//! let cases = [GoldenCase {
//!     name: "get_agent",
//!     route: "/agents/{id}",
//!     method: Method::GET,
//!     current: json!({ "id": "a1", "label": "pr-reviewer" }),
//! }];
//!
//! assert_golden_responses(&registry, &versions, &cases, "tests/golden/agents");
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use ferrlabs_api_version::{ApiVersion, TransformRegistry};
use http::Method;
use serde_json::Value;

/// One route's current-shape response, to be rendered at every checked
/// version.
///
/// `name` identifies the fixture file and has no bearing on routing; it only
/// needs to be unique within the cases passed to a single
/// [`assert_golden_responses`] call.
pub struct GoldenCase<'a> {
    pub name: &'a str,
    pub route: &'a str,
    pub method: Method,
    pub current: Value,
}

/// Render `case.current` through `registry` at every version in `versions`
/// and compare the result against a fixture under `fixtures_dir`.
///
/// Fixtures live at `{fixtures_dir}/{case.name}__{version}.json`. Set
/// `UPDATE_GOLDEN=1` in the environment to (re)write them from the current
/// registry output — the same workflow as `cargo insta review` or Jest's
/// `--updateSnapshot`, do that once, diff the fixture change in the PR that
/// introduced the transform, and commit it.
///
/// # Panics
///
/// Panics (via [`assert!`]) listing every mismatched or missing fixture, so
/// a single run surfaces every break rather than the first one.
pub fn assert_golden_responses(
    registry: &TransformRegistry,
    versions: &[ApiVersion],
    cases: &[GoldenCase<'_>],
    fixtures_dir: impl AsRef<Path>,
) {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    check_golden_responses(registry, versions, cases, fixtures_dir.as_ref(), update);
}

/// Core of [`assert_golden_responses`], with the update/compare choice taken
/// as a plain argument rather than read from the environment.
///
/// Kept separate so the harness's own tests can exercise both branches
/// without mutating process-global environment state, which `cargo test`
/// runs concurrently across threads.
fn check_golden_responses(
    registry: &TransformRegistry,
    versions: &[ApiVersion],
    cases: &[GoldenCase<'_>],
    fixtures_dir: &Path,
    update: bool,
) {
    let mut failures = Vec::new();

    for case in cases {
        for &version in versions {
            let mut rendered = case.current.clone();
            registry.downgrade_response(version, case.route, &case.method, &mut rendered);

            let path = fixture_path(fixtures_dir, case.name, version);
            if update {
                if let Err(err) = write_fixture(&path, &rendered) {
                    failures.push(format!(
                        "{}: could not write fixture: {err}",
                        path.display()
                    ));
                }
                continue;
            }

            match read_fixture(&path) {
                Ok(expected) if expected == rendered => {}
                Ok(expected) => failures.push(format!(
                    "{name} at {version} does not match {path}\n\
                     expected:\n{expected}\n\
                     actual:\n{actual}",
                    name = case.name,
                    path = path.display(),
                    expected = pretty(&expected),
                    actual = pretty(&rendered),
                )),
                Err(FixtureError::Missing) => failures.push(format!(
                    "{name} at {version}: no fixture at {path}; \
                     rerun with UPDATE_GOLDEN=1 to create it, then review the diff",
                    name = case.name,
                    path = path.display(),
                )),
                Err(FixtureError::Invalid(err)) => failures.push(format!(
                    "{path}: not valid JSON: {err}",
                    path = path.display()
                )),
            }
        }
    }

    assert!(
        failures.is_empty(),
        "golden API-version fixtures out of date:\n\n{}",
        failures.join("\n\n")
    );
}

fn fixture_path(dir: &Path, name: &str, version: ApiVersion) -> PathBuf {
    dir.join(format!("{name}__{version}.json"))
}

#[derive(Debug)]
enum FixtureError {
    Missing,
    Invalid(serde_json::Error),
}

fn read_fixture(path: &Path) -> Result<Value, FixtureError> {
    let contents = fs::read_to_string(path).map_err(|_| FixtureError::Missing)?;
    serde_json::from_str(&contents).map_err(FixtureError::Invalid)
}

fn write_fixture(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", pretty(value)))
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrlabs_api_version::Transform;
    use serde_json::json;

    fn version(raw: &str) -> ApiVersion {
        raw.parse().unwrap()
    }

    struct RenamedNameToLabel;

    impl Transform for RenamedNameToLabel {
        fn version(&self) -> ApiVersion {
            version("2026-09-01")
        }
        fn applies_to(&self, route: &str, _method: &Method) -> bool {
            route == "/agents/{id}"
        }
        fn downgrade_response(&self, body: &mut Value) {
            if let Some(label) = body.get("label").cloned() {
                body["name"] = label;
                if let Some(map) = body.as_object_mut() {
                    map.remove("label");
                }
            }
        }
    }

    fn registry() -> TransformRegistry {
        TransformRegistry::new().with(RenamedNameToLabel)
    }

    fn cases() -> Vec<GoldenCase<'static>> {
        vec![GoldenCase {
            name: "get_agent",
            route: "/agents/{id}",
            method: Method::GET,
            current: json!({ "id": "a1", "label": "pr-reviewer" }),
        }]
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "ferrlabs-testkit-golden-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default(),
        ));
        dir
    }

    #[test]
    fn writes_then_matches_its_own_fixtures() {
        let dir = scratch_dir("roundtrip");
        let versions = [version("2026-01-01"), version("2026-09-01")];

        check_golden_responses(&registry(), &versions, &cases(), &dir, true);
        check_golden_responses(&registry(), &versions, &cases(), &dir, false);

        let before = fixture_path(&dir, "get_agent", version("2026-01-01"));
        assert_eq!(
            read_fixture(&before).unwrap(),
            json!({ "id": "a1", "name": "pr-reviewer" })
        );
        let after = fixture_path(&dir, "get_agent", version("2026-09-01"));
        assert_eq!(
            read_fixture(&after).unwrap(),
            json!({ "id": "a1", "label": "pr-reviewer" })
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[should_panic(expected = "no fixture at")]
    fn a_missing_fixture_fails_with_a_clear_message() {
        let dir = scratch_dir("missing");
        check_golden_responses(&registry(), &[version("2026-01-01")], &cases(), &dir, false);
    }

    #[test]
    #[should_panic(expected = "does not match")]
    fn a_stale_fixture_fails_with_both_shapes() {
        let dir = scratch_dir("stale");
        fs::create_dir_all(&dir).unwrap();
        let path = fixture_path(&dir, "get_agent", version("2026-01-01"));
        fs::write(&path, r#"{"id":"a1","name":"wrong-shape"}"#).unwrap();

        check_golden_responses(&registry(), &[version("2026-01-01")], &cases(), &dir, false);

        let _ = fs::remove_dir_all(&dir);
    }
}
