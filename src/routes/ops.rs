use axum::{Router, routing::get};

use crate::handlers;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/health", get(handlers::ops::get_health))
        .route("/ready", get(handlers::ops::get_ready))
        .route("/metrics", get(handlers::ops::get_metrics))
        .route("/build", get(handlers::ops::get_build))
}
