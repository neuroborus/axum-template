use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

// NOTE: This template defines a full error taxonomy upfront.
// Most variants are not used by the minimal starter endpoints (e.g. /ops/health),
// so we intentionally silence `dead_code` warnings in this module.
// As the project grows, handlers/services should start using these variants.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Bad request: {message}")]
    BadRequest { message: String },

    #[error("Not found")]
    NotFound,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden")]
    Forbidden,

    #[error("Conflict: {message}")]
    Conflict { message: String },

    #[error("Internal error (id={error_id})")]
    Internal { error_id: Uuid },

    #[error("Request timeout")]
    Timeout,

    #[error("Service unavailable")]
    ServiceUnavailable,

    #[error("Payload too large")]
    PayloadTooLarge,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: &'static str,
    pub message: String,
    pub error_id: Option<String>,
}

#[allow(dead_code)]
impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    pub fn internal() -> Self {
        Self::Internal {
            error_id: Uuid::new_v4(),
        }
    }

    pub fn timeout() -> Self {
        Self::Timeout
    }

    pub fn service_unavailable() -> Self {
        Self::ServiceUnavailable
    }

    pub fn payload_too_large() -> Self {
        Self::PayloadTooLarge
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            Self::BadRequest { .. } => "bad_request",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Conflict { .. } => "conflict",
            Self::Internal { .. } => "internal",
            Self::Timeout => "timeout",
            Self::ServiceUnavailable => "service_unavailable",
            Self::PayloadTooLarge => "payload_too_large",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::BadRequest { message } => message.clone(),
            Self::NotFound => "Not found".to_string(),
            Self::Unauthorized => "Unauthorized".to_string(),
            Self::Forbidden => "Forbidden".to_string(),
            Self::Conflict { message } => message.clone(),
            Self::Internal { .. } => "Internal server error".to_string(),
            Self::Timeout => "Request timeout".to_string(),
            Self::ServiceUnavailable => "Service unavailable".to_string(),
            Self::PayloadTooLarge => "Payload too large".to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        let (error_id, should_log) = match &self {
            AppError::Internal { error_id } => (Some(error_id.to_string()), true),
            _ => (None, false),
        };

        if should_log {
            tracing::error!(error_id = %error_id.clone().unwrap_or_default(), "Unhandled internal error");
        }

        let body = ErrorResponse {
            code: self.error_code(),
            message: self.public_message(),
            error_id,
        };

        (status, Json(body)).into_response()
    }
}
