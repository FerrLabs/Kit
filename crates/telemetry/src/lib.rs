//! Tracing, metrics, and structured logging for FerrLabs APIs.
//!
//! Call [`init`] at the top of `main()` with the service name — sets up
//! `tracing-subscriber` with JSON output for log collectors and OTLP gRPC
//! export if `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
//!
//! Unmigrated: `_unmigrated/metrics.rs.unmigrated` is the raw port of
//! Application's Prometheus counters — needs registry injection before
//! it compiles standalone. Tracked in
//! [Kit#4](https://github.com/FerrLabs/Kit/issues/4).

pub struct TelemetryGuard;

pub fn init(_service_name: &str) -> anyhow::Result<TelemetryGuard> {
    // TODO: wire up tracing_subscriber registry with EnvFilter + JSON fmt
    // + OTLP exporter, flush on Drop.
    let _ = _service_name;
    Ok(TelemetryGuard)
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // TODO: flush OTLP exporter
    }
}
