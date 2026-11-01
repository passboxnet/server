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
    #[error("sign in again to confirm this change")]
    ReauthenticationRequired,
    #[error("the two-factor code is incorrect")]
    InvalidTwoFactorCode,
    #[error("the sign-in expired; start again")]
    TwoFactorExpired,
    #[error("too many attempts; try again later")]
    RateLimited(std::time::Duration),
    #[error("{message}")]
    Conflict { message: String, details: Value },
    /// The request is understood but not allowed, with a specific code such
    /// as `forbidden`, `account_disabled` or `registration_closed`.
    #[error("{message}")]
    Forbidden { code: &'static str, message: String },
    /// Refused with a code and details, for example by an organization
    /// gate (`crate::ext::Denial`), `org_read_only` or `family_limit_reached`.
    #[error("{message}")]
    Denied {
        code: &'static str,
        message: String,
        details: Value,
    },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::Forbidden {
            code,
            message: message.into(),
        }
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
            Self::ReauthenticationRequired => (StatusCode::FORBIDDEN, "reauthentication_required"),
            Self::InvalidTwoFactorCode => (StatusCode::UNAUTHORIZED, "invalid_two_factor_code"),
            Self::TwoFactorExpired => (StatusCode::UNAUTHORIZED, "two_factor_expired"),
            Self::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Conflict { .. } => (StatusCode::CONFLICT, "conflict"),
            Self::Forbidden { code, .. } | Self::Denied { code, .. } => {
                (StatusCode::FORBIDDEN, *code)
            }
            Self::Internal(err) => {
                tracing::error!(error = ?err, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let message = match &self {
            Self::Internal(_) => "internal server error".to_owned(),
            other => other.to_string(),
        };
        let retry_after = match &self {
            Self::RateLimited(wait) => Some(wait.as_secs().max(1)),
            _ => None,
        };
        let details = match self {
            Self::Conflict { details, .. } | Self::Denied { details, .. } => details,
            Self::RateLimited(_) => serde_json::json!({ "retryAfterSeconds": retry_after }),
            _ => Value::Null,
        };
        let mut response = (
            status,
            Json(ErrorBody {
                error: code,
                message,
                details,
            }),
        )
            .into_response();
        if let Some(seconds) = retry_after {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, seconds.into());
        }
        response
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
