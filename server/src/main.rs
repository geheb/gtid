use gtid_shared::config::AppConfig;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().expect(".env file required");

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = AppConfig::from_env();

    tracing::info!(
        "Starting GT Id - UI on localhost:{}, API on localhost:{}",
        config.ui_listen_port,
        config.api_listen_port
    );

    let _ = gtid_server::start_server(config).await;

    // Keep the main task alive forever
    std::future::pending::<()>().await;
}
