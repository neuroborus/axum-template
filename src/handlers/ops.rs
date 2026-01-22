use axum::{Json, extract::State};

use crate::dto::ops::{BuildResponse, EnvDto, MetricsResponse, StatusResponse};
use crate::error::AppError;
use crate::state::AppState;

#[utoipa::path(
    get,
    path = "/ops/health",
    responses((status = 200, description = "Service is healthy", body = StatusResponse)),
    tag = "ops"
)]
pub async fn get_health(State(_state): State<AppState>) -> Result<Json<StatusResponse>, AppError> {
    Ok(Json(StatusResponse {
        status: "ok".to_string(),
    }))
}

#[utoipa::path(
    get,
    path = "/ops/ready",
    responses((status = 200, description = "Service is ready", body = StatusResponse)),
    tag = "ops"
)]
pub async fn get_ready(State(_state): State<AppState>) -> Result<Json<StatusResponse>, AppError> {
    Ok(Json(StatusResponse {
        status: "ok".to_string(),
    }))
}

#[utoipa::path(
    get,
    path = "/ops/metrics",
    responses((status = 200, description = "Service metrics", body = MetricsResponse)),
    tag = "ops"
)]
pub async fn get_metrics(State(state): State<AppState>) -> Result<Json<MetricsResponse>, AppError> {
    let snapshot = state.metrics.snapshot();

    Ok(Json(MetricsResponse {
        uptime_seconds: snapshot.uptime_seconds,
        requests_total: snapshot.requests_total,
        responses_total: snapshot.responses_total,
        responses_2xx: snapshot.responses_2xx,
        responses_4xx: snapshot.responses_4xx,
        responses_5xx: snapshot.responses_5xx,
    }))
}

#[utoipa::path(
    get,
    path = "/ops/build",
    responses((status = 200, description = "Build metadata", body = BuildResponse)),
    tag = "ops"
)]
pub async fn get_build(State(state): State<AppState>) -> Result<Json<BuildResponse>, AppError> {
    let env = match state.settings.app_env {
        crate::config::AppEnv::Development => EnvDto::Development,
        crate::config::AppEnv::Production => EnvDto::Production,
    };

    Ok(Json(BuildResponse {
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        env,
    }))
}
