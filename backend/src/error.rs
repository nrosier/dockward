use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Application error. Each variant maps to one HTTP status and one snake_case
/// code from the error envelope in `specs/api.md`.
///
/// Messages are safe to show to users. They never contain secrets, tokens, SQL,
/// or stack traces.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Variants are constructed by the handlers and services added later.
pub enum AppError {
    InvalidRequest(String),
    PasswordTooShort,
    Unauthenticated,
    InvalidCredentials,
    Forbidden,
    CsrfInvalid,
    NotFound,
    Conflict(String),
    ValidationFailed(String),
    PayloadTooLarge,
    RateLimited,
    InternalError,
    UpstreamUnreachable,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl AppError {
    /// The HTTP status for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::InvalidRequest(_) | AppError::PasswordTooShort => StatusCode::BAD_REQUEST,
            AppError::Unauthenticated | AppError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AppError::Forbidden | AppError::CsrfInvalid => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::UpstreamUnreachable => StatusCode::BAD_GATEWAY,
        }
    }

    /// The snake_case code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::InvalidRequest(_) => "invalid_request",
            AppError::PasswordTooShort => "password_too_short",
            AppError::Unauthenticated => "unauthenticated",
            AppError::InvalidCredentials => "invalid_credentials",
            AppError::Forbidden => "forbidden",
            AppError::CsrfInvalid => "csrf_invalid",
            AppError::NotFound => "not_found",
            AppError::Conflict(_) => "conflict",
            AppError::ValidationFailed(_) => "validation_failed",
            AppError::PayloadTooLarge => "payload_too_large",
            AppError::RateLimited => "rate_limited",
            AppError::InternalError => "internal_error",
            AppError::UpstreamUnreachable => "upstream_unreachable",
        }
    }

    /// The safe, user-facing message.
    pub fn message(&self) -> String {
        match self {
            AppError::InvalidRequest(detail)
            | AppError::Conflict(detail)
            | AppError::ValidationFailed(detail) => detail.clone(),
            AppError::PasswordTooShort => "Password must be at least 15 characters.".to_owned(),
            AppError::Unauthenticated => "Authentication is required.".to_owned(),
            AppError::InvalidCredentials => "Invalid username or password.".to_owned(),
            AppError::Forbidden => "You do not have permission to do this.".to_owned(),
            AppError::CsrfInvalid => "The request could not be verified.".to_owned(),
            AppError::NotFound => "The requested item was not found.".to_owned(),
            AppError::PayloadTooLarge => "The request body is too large.".to_owned(),
            AppError::RateLimited => "Too many requests. Try again later.".to_owned(),
            AppError::InternalError => "An internal error occurred.".to_owned(),
            AppError::UpstreamUnreachable => "An upstream service could not be reached.".to_owned(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code(),
                message: self.message(),
            },
        };
        (self.status(), Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn render(err: AppError) -> (StatusCode, serde_json::Value) {
        let response = err.into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4096)
            .await
            .unwrap_or_default();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[test]
    fn each_variant_maps_to_its_status_and_code() {
        let cases = [
            (AppError::InvalidRequest("x".into()), 400, "invalid_request"),
            (AppError::PasswordTooShort, 400, "password_too_short"),
            (AppError::Unauthenticated, 401, "unauthenticated"),
            (AppError::InvalidCredentials, 401, "invalid_credentials"),
            (AppError::Forbidden, 403, "forbidden"),
            (AppError::CsrfInvalid, 403, "csrf_invalid"),
            (AppError::NotFound, 404, "not_found"),
            (AppError::Conflict("x".into()), 409, "conflict"),
            (
                AppError::ValidationFailed("x".into()),
                422,
                "validation_failed",
            ),
            (AppError::PayloadTooLarge, 413, "payload_too_large"),
            (AppError::RateLimited, 429, "rate_limited"),
            (AppError::InternalError, 500, "internal_error"),
            (AppError::UpstreamUnreachable, 502, "upstream_unreachable"),
        ];
        for (err, status, code) in cases {
            assert_eq!(err.status().as_u16(), status, "status for {code}");
            assert_eq!(err.code(), code);
        }
    }

    #[tokio::test]
    async fn envelope_has_code_and_message() {
        let (status, json) = render(AppError::NotFound).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["error"]["code"], "not_found");
        assert_eq!(
            json["error"]["message"],
            "The requested item was not found."
        );
    }

    #[tokio::test]
    async fn internal_error_hides_detail() {
        let (status, json) = render(AppError::InternalError).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"]["code"], "internal_error");
        assert_eq!(json["error"]["message"], "An internal error occurred.");
    }

    #[test]
    fn messages_are_never_empty() {
        for err in [
            AppError::PasswordTooShort,
            AppError::Unauthenticated,
            AppError::InternalError,
            AppError::RateLimited,
        ] {
            assert!(!err.message().is_empty());
        }
    }
}
