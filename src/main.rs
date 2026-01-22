mod app;
mod config;
mod dto;
mod error;
mod handlers;
mod routes;
mod state;

use crate::config::Settings;
use crate::state::AppState;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let settings = Settings::from_env()?;
    config::init_tracing(&settings);

    let addr = settings.socket_addr();

    // build_router() returns Router<()> with state already applied.
    let state = AppState::new(settings);
    let app = app::build_router(state);

    tracing::info!(%addr, "Listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("Shutdown signal received");
}
