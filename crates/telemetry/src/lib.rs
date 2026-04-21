//! Tracing, metrics, and structured logging for FerrLabs APIs.
//!
//! Call [`init`] at the top of `main()` with the service name — sets up
//! `tracing-subscriber` with JSON output for stdout (for log collectors)
//! and OTLP gRPC export to your OpenTelemetry collector if `OTEL_EXPORTER_OTLP_ENDPOINT`
//! is set.

use anyhow::Context;

pub struct TelemetryGuard;

pub fn init(_service_name: &str) -> anyhow::Result<TelemetryGuard> {
    // TODO:
    // - tracing_subscriber::registry()
    //     .with(EnvFilter::from_default_env())
    //     .with(fmt::layer().json())
    //     .with(opentelemetry_layer)
    //     .init()
    // - opentelemetry OTLP exporter conditional on OTEL_EXPORTER_OTLP_ENDPOINT
    let _ = _service_name;
    Ok(TelemetryGuard).context("telemetry init placeholder")
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // TODO: flush OTLP exporter on shutdown
    }
}
