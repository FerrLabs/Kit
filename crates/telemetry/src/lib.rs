//! Tracing, metrics, and structured logging for `FerrLabs` APIs.
//!
//! Call [`init`] at the top of `main()` with the service name — sets up
//! `tracing-subscriber` with JSON output for log collectors and OTLP gRPC
//! export if `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
//!
//! With the `metrics` feature, [`metrics`] adds Prometheus HTTP request
//! metrics: a [`metrics::track`] axum middleware and a self-contained
//! [`metrics::serve`] `/metrics` server for a private (non-ingress) port. The
//! `service` label is applied by Prometheus at scrape time, so one binary works
//! under any service name. Services register extra collectors on
//! [`metrics::registry`].
//!
//! The [`events`] module is a separate, transport-agnostic registry of
//! product-analytics events (org/auth/cli/per-product). It does not depend
//! on tracing or OTLP and is intended to be consumed by every FerrLabs
//! product, including CLIs.

pub mod events;

#[cfg(feature = "metrics")]
pub mod metrics;

use std::env;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

#[must_use]
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

/// Initialise structured logging and (optionally) OTLP trace export.
///
/// Installs a global [`tracing_subscriber`] registry with an
/// [`EnvFilter`] (honouring `RUST_LOG`, defaulting to `info`) and a JSON
/// formatting layer. When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, a batched
/// OTLP/gRPC span exporter is attached and its provider is held in the
/// returned guard so it is flushed when the guard is dropped.
///
/// Keep the returned [`TelemetryGuard`] alive for the lifetime of the
/// process; dropping it flushes any buffered spans.
///
/// # Errors
/// Returns an error if a global subscriber is already installed or if the
/// OTLP exporter cannot be constructed.
pub fn init(service_name: &str) -> anyhow::Result<TelemetryGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    let provider = if env::var_os(OTLP_ENDPOINT_ENV).is_some() {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()?;
        let resource = Resource::builder()
            .with_service_name(service_name.to_owned())
            .build();
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();
        opentelemetry::global::set_tracer_provider(provider.clone());
        Some(provider)
    } else {
        None
    };

    let otel_layer = provider
        .as_ref()
        .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer(service_name.to_owned())));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()?;

    Ok(TelemetryGuard { provider })
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_installs_a_global_subscriber_and_is_idempotent_failure() {
        let endpoint_set = env::var_os(OTLP_ENDPOINT_ENV).is_some();

        let guard = init("ferrlabs-telemetry-test").expect("first init should succeed");
        assert_eq!(
            guard.provider.is_some(),
            endpoint_set,
            "an OTLP provider is built iff the endpoint env is set"
        );

        assert!(
            init("ferrlabs-telemetry-test").is_err(),
            "init must install a global subscriber, so a second call has to fail"
        );
    }
}
