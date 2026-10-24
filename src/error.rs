use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;

/// Errors returned by API handlers. Internal details are logged, never sent.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("not found")]
    NotFound,
    #[error("{message}")]
    Conflict { message: String, details: Value },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    pub fn conflict(message: impl Into<String>, details: Value) -> Self {
        Self::Conflict {
            message: message.into(),
            details,
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        Self::Internal(err.into())
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    details: Value,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict { .. } => (StatusCode::CONFLICT, "conflict"),
            Self::Internal(err) => {
                tracing::error!(error = ?err, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let message = match &self {
            Self::Internal(_) => "internal server error".to_owned(),
            other => other.to_string(),
        };
        let details = match self {
            Self::Conflict { details, .. } => details,
            _ => Value::Null,
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                message,
                details,
            }),
        )
            .into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
