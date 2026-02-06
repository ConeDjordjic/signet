use signet::{
    cache::create_redis_pool,
    create_db_pool, create_router,
    events::EventPublisherBuilder,
    grpc::{proto::auth_service_server::AuthServiceServer, AuthServiceImpl},
    init_tracing, shutdown_telemetry, AppState, Config,
};
use tonic::transport::{Identity, Server as TonicServer, ServerTlsConfig};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    let config = Config::from_env();

    init_tracing(&config);

    info!(
        service = "signet",
        version = env!("CARGO_PKG_VERSION"),
        environment = ?config.server.environment,
        "Starting server"
    );

    let issues = config.validate_for_production();
    if !issues.is_empty() {
        for issue in &issues {
            warn!(issue = %issue, "Configuration warning");
        }
    }

    info!(
        database_url = %config.database.url.split('@').next_back().unwrap_or("***"),
        max_connections = config.database.max_connections,
        "Connecting to database"
    );

    let db_pool = create_db_pool(&config);

    info!("Database connection pool created");

    let redis_pool = create_redis_pool(&config.redis);
    let publisher_shutdown = EventPublisherBuilder::new(db_pool.clone())
        .maybe_redis_pool(redis_pool.clone())
        .spawn();

    let state = AppState::new(db_pool.clone(), redis_pool, &config);
    let app = create_router(state.clone(), &config);

    let http_addr = config.server_addr();
    let listener = tokio::net::TcpListener::bind(&http_addr)
        .await
        .unwrap_or_else(|e| {
            error!(error = %e, address = %http_addr, "Failed to bind HTTP server");
            std::process::exit(1);
        });

    info!(
        http_address = %http_addr,
        docs_url = %format!("http://{}/swagger-ui", http_addr),
        "HTTP server ready"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    let http_server = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        async move {
            let shutdown_signal = async move {
                let _ = shutdown_rx.recv().await;
            };
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal)
            .await
        }
    };

    let grpc_server = if config.grpc.enabled {
        let grpc_addr = format!("{}:{}", config.server.host, config.grpc.port)
            .parse()
            .expect("Invalid gRPC address");

        let auth_service = AuthServiceImpl::new(db_pool, state.jwt_config.clone());

        let tls_config = if config.grpc.tls_enabled() {
            let cert = std::fs::read_to_string(config.grpc.tls_cert_path.as_ref().unwrap())
                .expect("Failed to read gRPC TLS certificate");
            let key = std::fs::read_to_string(config.grpc.tls_key_path.as_ref().unwrap())
                .expect("Failed to read gRPC TLS key");
            let identity = Identity::from_pem(cert, key);
            Some(ServerTlsConfig::new().identity(identity))
        } else {
            None
        };

        info!(
            grpc_address = %grpc_addr,
            tls = tls_config.is_some(),
            "gRPC server ready"
        );

        let mut shutdown_rx = shutdown_tx.subscribe();
        Some(async move {
            let mut builder = TonicServer::builder();
            if let Some(tls) = tls_config {
                builder = builder.tls_config(tls).expect("Invalid TLS config");
            }
            builder
                .add_service(AuthServiceServer::new(auth_service))
                .serve_with_shutdown(grpc_addr, async move {
                    let _ = shutdown_rx.recv().await;
                })
                .await
        })
    } else {
        None
    };

    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        info!("Shutdown signal received");
        let _ = shutdown_tx.send(());
    };

    tokio::select! {
        result = http_server => {
            if let Err(e) = result {
                error!(error = %e, "HTTP server error");
            }
        }
        result = async {
            if let Some(server) = grpc_server {
                server.await
            } else {
                std::future::pending().await
            }
        } => {
            if let Err(e) = result {
                error!(error = %e, "gRPC server error");
            }
        }
        _ = ctrl_c => {}
    }

    drop(shutdown_rx);

    info!("Shutting down event publisher...");
    let _ = publisher_shutdown.send(true);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    shutdown_telemetry();

    info!("Server shutdown complete");
}
