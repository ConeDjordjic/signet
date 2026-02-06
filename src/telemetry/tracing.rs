//! Tracing configuration with OpenTelemetry support.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::{Config, LogFormat, TelemetryConfig};

pub fn init_telemetry(config: &Config) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    let tracer = create_otel_tracer(&config.telemetry);

    match (&config.logging.format, tracer) {
        (LogFormat::Json, Some(t)) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .with(tracing_opentelemetry::layer().with_tracer(t))
                .init();
        }
        (LogFormat::Json, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        (LogFormat::Pretty, Some(t)) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .with(tracing_opentelemetry::layer().with_tracer(t))
                .init();
        }
        (LogFormat::Pretty, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }
}

fn create_otel_tracer(config: &TelemetryConfig) -> Option<sdktrace::Tracer> {
    let endpoint = config.otlp_endpoint.as_ref()?;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .ok()?;

    let resource = Resource::new(vec![KeyValue::new(
        "service.name",
        config.service_name.clone(),
    )]);

    let provider = sdktrace::TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer("signet");

    global::set_tracer_provider(provider);

    Some(tracer)
}

pub fn shutdown_telemetry() {
    global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_otel_tracer_without_endpoint() {
        let config = TelemetryConfig {
            otlp_endpoint: None,
            service_name: "test".to_string(),
            metrics_enabled: false,
        };

        let tracer = create_otel_tracer(&config);
        assert!(tracer.is_none());
    }
}
