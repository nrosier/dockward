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
    /// The Harbor repository is already mapped on this Harbor instance, by any user. A
    /// `409 conflict` with the fixed `harbor_repository_mapped` detail and fixed text that
    /// never names the other mapping, its owner or its id (`specs/api.md`, #180).
    HarborRepositoryMapped,
    ValidationFailed(String),
    /// GitHub cannot take code scanning uploads for the repository (`specs/security.md`).
    CodeScanningUnavailable,
    PayloadTooLarge,
    RateLimited,
    InternalError,
    /// `HARBORGATE_BACKUP_DIR` is missing, not a directory, or not writable. Returned
    /// as `500 internal_error` with a safe message that names the cause
    /// (`specs/security.md`, Backup and restore).
    BackupDirUnavailable,
    UpstreamUnreachable,
    /// The upstream registry answered `401` or `403` and would not accept the credentials
    /// (`specs/spinoff-local-scan.md`, section 6). Fixed text; no registry body or header.
    UpstreamAuthRejected,
    /// The upstream registry sent content that failed verification: a digest mismatch or a
    /// malformed manifest or index (`specs/spinoff-local-scan.md`, sections 3 and 6).
    UpstreamContentInvalid,
    /// An image is larger than the pull cap (`specs/spinoff-local-scan.md`, sections 3 and 13).
    ImageTooLarge,
    /// The registry answered a status the client does not handle. Only the number is kept, and
    /// the body and headers are discarded (`specs/spinoff-local-scan.md`, section 6).
    UpstreamStatus(u16),
    /// The free-disk guard refused a pull (`specs/spinoff-local-scan.md`, sections 4 and 13).
    /// Not an HTTP response. The job maps it to its fixed `last_error` text.
    InsufficientDisk,
    /// A scanner run failed. Not an HTTP response: the job stores the fixed text of the fault
    /// as its `last_error` (`specs/spinoff-local-scan.md`, section 6).
    Scanner(ScannerFault),
    /// The database file holds the table of an older HarborGate schema and cannot be used
    /// (specs/spinoff-local-scan.md, section 9). Refused at pool open. Fixed text only.
    LegacyDatabase,
}

/// A scanner run failure. Each variant has one fixed text from `specs/spinoff-local-scan.md`,
/// section 6. No scanner stderr, output, path or argument is ever part of the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerFault {
    /// The run exceeded its timeout and its process group was killed.
    TimedOut,
    /// The captured output went over the cap.
    OutputTooLarge,
    /// The scanner exited non-zero, or could not be started.
    Failed,
    /// The scanner output could not be parsed or failed the strict schema checks.
    OutputNotRecognised,
    /// The scanner vulnerability database is missing or unreadable.
    DatabaseNotAvailable,
}

impl ScannerFault {
    /// The fixed text stored as a job's `last_error`.
    pub fn text(self) -> &'static str {
        match self {
            ScannerFault::TimedOut => "scanner timed out",
            ScannerFault::OutputTooLarge => "scanner output too large",
            ScannerFault::Failed => "scanner failed",
            ScannerFault::OutputNotRecognised => "scanner output not recognised",
            ScannerFault::DatabaseNotAvailable => "scanner database not available",
        }
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    /// Optional fixed sub-code that tells a client which fix applies when one `code` covers
    /// several causes (`specs/api.md`, Error envelope). Absent for every other error.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<ErrorDetail>,
}

/// The fixed `detail` codes of the error envelope. Only the picker `422` answers set one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorDetail {
    /// The Harbor credential does not authenticate as a robot.
    HarborIdentity,
    /// The Harbor robot lacks a permission the picker needs.
    RobotScope,
    /// The GitHub token is invalid or cannot list repositories.
    GithubToken,
    /// The credential is the wrong type for the route.
    WrongCredentialType,
    /// A mapping create or update names a Harbor repository that is already mapped.
    HarborRepositoryMapped,
}

/// Builds an error envelope response. Every error response is built here, so the envelope
/// has one shape.
pub fn envelope_response(
    status: StatusCode,
    code: &'static str,
    message: String,
    detail: Option<ErrorDetail>,
) -> Response {
    let body = ErrorEnvelope {
        error: ErrorBody {
            code,
            message,
            detail,
        },
    };
    (status, Json(body)).into_response()
}

impl AppError {
    /// The HTTP status for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::InvalidRequest(_) | AppError::PasswordTooShort => StatusCode::BAD_REQUEST,
            AppError::Unauthenticated | AppError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AppError::Forbidden | AppError::CsrfInvalid => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) | AppError::HarborRepositoryMapped => StatusCode::CONFLICT,
            AppError::ValidationFailed(_) | AppError::CodeScanningUnavailable => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::InternalError | AppError::BackupDirUnavailable => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::UpstreamUnreachable
            | AppError::UpstreamAuthRejected
            | AppError::UpstreamContentInvalid => StatusCode::BAD_GATEWAY,
            AppError::UpstreamStatus(_) => StatusCode::BAD_GATEWAY,
            AppError::ImageTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::InsufficientDisk => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Scanner(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::LegacyDatabase => StatusCode::INTERNAL_SERVER_ERROR,
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
            AppError::Conflict(_) | AppError::HarborRepositoryMapped => "conflict",
            AppError::ValidationFailed(_) => "validation_failed",
            AppError::CodeScanningUnavailable => "code_scanning_unavailable",
            AppError::PayloadTooLarge => "payload_too_large",
            AppError::RateLimited => "rate_limited",
            AppError::InternalError | AppError::BackupDirUnavailable => "internal_error",
            AppError::UpstreamUnreachable
            | AppError::UpstreamAuthRejected
            | AppError::UpstreamContentInvalid => "upstream_unreachable",
            AppError::UpstreamStatus(_) => "upstream_unreachable",
            AppError::ImageTooLarge => "payload_too_large",
            AppError::InsufficientDisk => "internal_error",
            AppError::Scanner(_) => "internal_error",
            AppError::LegacyDatabase => "internal_error",
        }
    }

    /// The safe, user-facing message.
    pub fn message(&self) -> String {
        match self {
            AppError::InvalidRequest(detail)
            | AppError::Conflict(detail)
            | AppError::ValidationFailed(detail) => detail.clone(),
            AppError::PasswordTooShort => {
                "Password must be between 15 and 64 characters.".to_owned()
            }
            AppError::CodeScanningUnavailable => {
                "This repository cannot receive code scanning uploads.".to_owned()
            }
            AppError::HarborRepositoryMapped => {
                "This Harbor repository is already mapped on this instance.".to_owned()
            }
            AppError::Unauthenticated => "Authentication is required.".to_owned(),
            AppError::InvalidCredentials => "Invalid username or password.".to_owned(),
            AppError::Forbidden => "You do not have permission to do this.".to_owned(),
            AppError::CsrfInvalid => "The request could not be verified.".to_owned(),
            AppError::NotFound => "The requested item was not found.".to_owned(),
            AppError::PayloadTooLarge => "The request body is too large.".to_owned(),
            AppError::RateLimited => "Too many requests. Try again later.".to_owned(),
            AppError::InternalError => "An internal error occurred.".to_owned(),
            AppError::BackupDirUnavailable => {
                "The backup directory is missing or not writable.".to_owned()
            }
            AppError::UpstreamUnreachable => "An upstream service could not be reached.".to_owned(),
            AppError::UpstreamAuthRejected => {
                "The upstream registry rejected the credentials.".to_owned()
            }
            AppError::UpstreamContentInvalid => {
                "The upstream registry sent content that could not be verified.".to_owned()
            }
            AppError::UpstreamStatus(_) => "An upstream service could not be reached.".to_owned(),
            AppError::ImageTooLarge => "The image is larger than the allowed size.".to_owned(),
            AppError::InsufficientDisk => "An internal error occurred.".to_owned(),
            AppError::Scanner(fault) => fault.text().to_owned(),
            AppError::LegacyDatabase => {
                "this database was created by HarborGate and cannot be used by this version"
                    .to_owned()
            }
        }
    }

    /// The fixed `detail` code, for the errors that carry one.
    pub fn detail(&self) -> Option<ErrorDetail> {
        match self {
            AppError::HarborRepositoryMapped => Some(ErrorDetail::HarborRepositoryMapped),
            _ => None,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        envelope_response(self.status(), self.code(), self.message(), self.detail())
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
            (AppError::HarborRepositoryMapped, 409, "conflict"),
            (
                AppError::ValidationFailed("x".into()),
                422,
                "validation_failed",
            ),
            (AppError::PayloadTooLarge, 413, "payload_too_large"),
            (
                AppError::CodeScanningUnavailable,
                422,
                "code_scanning_unavailable",
            ),
            (AppError::RateLimited, 429, "rate_limited"),
            (AppError::InternalError, 500, "internal_error"),
            (AppError::BackupDirUnavailable, 500, "internal_error"),
            (AppError::UpstreamUnreachable, 502, "upstream_unreachable"),
            (AppError::UpstreamAuthRejected, 502, "upstream_unreachable"),
            (
                AppError::UpstreamContentInvalid,
                502,
                "upstream_unreachable",
            ),
            (AppError::UpstreamStatus(503), 502, "upstream_unreachable"),
            (AppError::ImageTooLarge, 413, "payload_too_large"),
            (AppError::InsufficientDisk, 500, "internal_error"),
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
    async fn existing_errors_carry_no_detail_key() {
        for err in [
            AppError::NotFound,
            AppError::ValidationFailed("x".into()),
            AppError::UpstreamUnreachable,
        ] {
            let (_, json) = render(err).await;
            assert!(json["error"].get("detail").is_none(), "{json}");
        }
    }

    #[test]
    fn detail_codes_serialize_as_fixed_snake_case() {
        for (detail, text) in [
            (ErrorDetail::HarborIdentity, "harbor_identity"),
            (ErrorDetail::RobotScope, "robot_scope"),
            (ErrorDetail::GithubToken, "github_token"),
            (ErrorDetail::WrongCredentialType, "wrong_credential_type"),
            (
                ErrorDetail::HarborRepositoryMapped,
                "harbor_repository_mapped",
            ),
        ] {
            assert_eq!(serde_json::to_value(detail).unwrap(), text);
        }
    }

    #[tokio::test]
    async fn harbor_repository_mapped_has_fixed_detail_and_text() {
        let (status, json) = render(AppError::HarborRepositoryMapped).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["error"]["code"], "conflict");
        assert_eq!(json["error"]["detail"], "harbor_repository_mapped");
        assert_eq!(
            json["error"]["message"],
            "This Harbor repository is already mapped on this instance."
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
