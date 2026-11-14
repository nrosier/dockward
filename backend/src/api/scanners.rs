//! `POST /api/v1/admin/scanners/{scanner}/install` and `.../rollback` (#403). Admin only; the
//! CSRF guard of the router covers both. The answer names the scanner and the version, or a
//! fixed error kind. It never holds a path, a URL or an upstream body.

use std::time::Instant;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::api::auth::AdminUser;
use crate::api::hardening::too_many_requests;
use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::scanner::Scanner;
use crate::services::scanner::install::InstallError;
use crate::services::scanner::version::Version;

/// The success body: the scanner and the version now current, `vX.Y.Z`.
#[derive(Debug, Serialize)]
struct Done {
    scanner: &'static str,
    version: String,
}

/// The status of a refused install or rollback.
fn status(err: InstallError) -> StatusCode {
    match err {
        InstallError::Busy
        | InstallError::NoPrevious
        | InstallError::UnsupportedPlatform
        | InstallError::BundledUnknown
        | InstallError::NotNewer
        | InstallError::AlreadyInstalled => StatusCode::CONFLICT,
        InstallError::ReleaseUnavailable
        | InstallError::DownloadFailed
        | InstallError::DownloadTooLarge
        | InstallError::ChecksumMissing
        | InstallError::ChecksumMismatch
        | InstallError::SignatureInvalid
        | InstallError::ArchiveRefused => StatusCode::BAD_GATEWAY,
        InstallError::Storage => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// The error envelope with the fixed `kind` of the refusal:
/// `{"error":{"code","message"},"kind"}`.
fn refused(err: InstallError) -> Response {
    let status = status(err);
    let code = match status {
        StatusCode::CONFLICT => "conflict",
        StatusCode::BAD_GATEWAY => "upstream_unreachable",
        _ => "internal_error",
    };
    let message = match err {
        InstallError::Busy => "Another scanner install or rollback is running.",
        InstallError::NoPrevious => "No previous scanner version is kept.",
        InstallError::NotNewer | InstallError::AlreadyInstalled => {
            "No newer scanner release is available."
        }
        InstallError::UnsupportedPlatform | InstallError::BundledUnknown => {
            "The scanner cannot be updated on this installation."
        }
        InstallError::ChecksumMissing
        | InstallError::ChecksumMismatch
        | InstallError::SignatureInvalid
        | InstallError::ArchiveRefused => "The scanner release failed verification.",
        InstallError::ReleaseUnavailable
        | InstallError::DownloadFailed
        | InstallError::DownloadTooLarge => "The scanner release could not be downloaded.",
        InstallError::Storage => "An internal error occurred.",
    };
    let body = serde_json::json!({
        "error": {"code": code, "message": message},
        "kind": err.kind(),
    });
    (status, Json(body)).into_response()
}

async fn record(
    state: &AppState,
    admin: &crate::services::sessions::AuthUser,
    action: &str,
    scanner: Scanner,
    version: Version,
) -> Result<(), AppError> {
    let actor = Actor {
        user_id: Some(admin.id.clone()),
        username: admin.username.clone(),
    };
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| AppError::InternalError)?;
    let details = serde_json::json!({"scanner": scanner.key(), "version": version.tagged()});
    audit::record(
        &mut tx,
        &actor,
        action,
        &format!("scanner:{}", scanner.key()),
        Some(&details),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)
}

fn done(scanner: Scanner, version: Version) -> Response {
    Json(Done {
        scanner: scanner.key(),
        version: version.tagged(),
    })
    .into_response()
}

/// Installs the latest stable release of `scanner` when its SHA-256 matches the upstream
/// checksums file and that file's Sigstore bundle verifies against the release identity.
/// `200 {"scanner","version"}`; `404` for an unknown scanner; `429` over the limit; `409`, `502`
/// or `500` with a fixed `kind` when nothing was installed. Audited as `scanner.install`.
pub async fn install(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    let scanner = Scanner::from_key(&key).ok_or(AppError::NotFound)?;
    if let Err(retry_after) = state
        .scanner_install_limiter
        .check(scanner.key(), Instant::now())
    {
        return Ok(too_many_requests(retry_after));
    }
    match state.scanner_installer.install(scanner).await {
        Ok(version) => {
            record(&state, &admin, "scanner.install", scanner, version).await?;
            Ok(done(scanner, version))
        }
        Err(err) => Ok(refused(err)),
    }
}

/// Switches `scanner` back to the previous downloaded version. `200 {"scanner","version"}`;
/// `404` for an unknown scanner; `409 no_previous_version` when none is kept. Audited as
/// `scanner.rollback`.
pub async fn rollback(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    let scanner = Scanner::from_key(&key).ok_or(AppError::NotFound)?;
    match state.scanner_installer.rollback(scanner).await {
        Ok(version) => {
            record(&state, &admin, "scanner.rollback", scanner, version).await?;
            Ok(done(scanner, version))
        }
        Err(err) => Ok(refused(err)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use serde_json::Value;

    use crate::api::admin::test_support::{seed_user, test_state};
    use crate::services::scanner::Scanner;
    use crate::services::scanner::install::Installer;
    use crate::services::scanner::install::tests::{BUNDLED, Upstream, serve, verifier};
    use crate::services::scanner::selection::ScannerPrograms;
    use crate::services::scanner::volume::ScannerVolume;
    use crate::services::scanner::volume::tests::{ExpectTestOk, place, v};
    use crate::tests::{get_json, send_json, session_cookie};
    use crate::{auth, config};

    struct Fx {
        router: axum::Router,
        pool: sqlx::SqlitePool,
        dir: std::path::PathBuf,
        csrf: String,
        admin: String,
        user: String,
        anonymous: String,
    }

    async fn fx(name: &str) -> Fx {
        let (mut state, dir) = test_state(name).await;
        seed_user(&state.pool, "adm", "admin").await;
        seed_user(&state.pool, "usr", "user").await;
        let volume = ScannerVolume::under(&dir);
        place(&volume, Scanner::Trivy, v("0.76.5"), "old");
        volume
            .record_current(Scanner::Trivy, v("0.76.5"))
            .expect_test_ok();
        let programs = Arc::new(ScannerPrograms::bundled(&dir).select_at_startup(BUNDLED));
        let (port, root, _) = serve(Upstream::good()).await;
        state.scanner_programs = programs.clone();
        state.scanner_installer = Arc::new(Installer::local(
            &dir,
            programs,
            BUNDLED,
            port,
            root,
            verifier(true),
        ));
        state.about = Arc::new(crate::services::about::About {
            dockward: "0.0.0".to_owned(),
            trivy: Some("v0.76.2".to_owned()),
            grype: Some("v0.121.3".to_owned()),
        });
        let pool = state.pool.clone();
        let root =
            config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let csrf = auth::csrf::issue(&auth::crypto::csrf_key(&root).unwrap()).unwrap();
        let csrf_cookie = format!("{}={csrf}", auth::csrf::CSRF_COOKIE);
        let cookie =
            |id: &str, role: &str| format!("{}; {csrf_cookie}", session_cookie(id, role, 0));
        Fx {
            router: crate::app(Vec::new(), state),
            pool,
            admin: cookie("adm", "admin"),
            user: cookie("usr", "user"),
            anonymous: csrf_cookie.clone(),
            csrf,
            dir,
        }
    }

    impl Fx {
        async fn post(&self, uri: &str, who: &str, csrf: Option<&str>) -> (StatusCode, Value) {
            send_json(&self.router, "POST", uri, Some(who), csrf, "").await
        }

        async fn finish(self) {
            self.pool.close().await;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const INSTALL: &str = "/api/v1/admin/scanners/trivy/install";
    const ROLLBACK: &str = "/api/v1/admin/scanners/trivy/rollback";

    #[tokio::test]
    async fn the_install_route_requires_an_admin_session_and_csrf_and_returns_no_path() {
        let fx = fx("scanner-install-route").await;
        let csrf = fx.csrf.clone();
        // No session, a regular user, and an admin without the CSRF header: nothing installs.
        assert_eq!(
            fx.post(INSTALL, &fx.anonymous, Some(&csrf)).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            fx.post(INSTALL, &fx.user, Some(&csrf)).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, body) = fx.post(INSTALL, &fx.admin, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "csrf_invalid");
        let volume = ScannerVolume::under(&fx.dir);
        assert!(!volume.version_dir(Scanner::Trivy, v("0.77.0")).exists());

        // The admin with CSRF installs.
        let (status, body) = fx.post(INSTALL, &fx.admin, Some(&csrf)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            serde_json::json!({"scanner": "trivy", "version": "v0.77.0"})
        );
        let text = body.to_string();
        let dir_text = fx.dir.to_string_lossy().to_string();
        assert!(!text.contains('/') && !text.contains(&dir_text), "{text}");
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'scanner.install' AND target = 'scanner:trivy'",
        )
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(audits, 1);

        // About reflects the new current version.
        let (status, about) = get_json(&fx.router, "/api/v1/about", &fx.admin).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(about["scanners"]["trivy"]["in_use"], "downloaded");
        assert_eq!(about["scanners"]["trivy"]["downloaded_version"], "v0.77.0");

        // A second install is refused with a fixed kind and no path.
        let (status, body) = fx.post(INSTALL, &fx.admin, Some(&csrf)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["kind"], "already_installed");
        assert!(!body.to_string().contains(&dir_text));

        // An unknown scanner is 404.
        assert_eq!(
            fx.post(
                "/api/v1/admin/scanners/clair/install",
                &fx.admin,
                Some(&csrf)
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        fx.finish().await;
    }

    #[tokio::test]
    async fn the_rollback_route_swaps_back_and_refuses_with_no_previous() {
        let fx = fx("scanner-rollback-route").await;
        let csrf = fx.csrf.clone();
        assert_eq!(
            fx.post(ROLLBACK, &fx.user, Some(&csrf)).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            fx.post(ROLLBACK, &fx.admin, None).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, body) = fx.post(ROLLBACK, &fx.admin, Some(&csrf)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["kind"], "no_previous_version");

        assert_eq!(
            fx.post(INSTALL, &fx.admin, Some(&csrf)).await.0,
            StatusCode::OK
        );
        let (status, body) = fx.post(ROLLBACK, &fx.admin, Some(&csrf)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({"scanner": "trivy", "version": "v0.76.5"})
        );
        let (_, about) = get_json(&fx.router, "/api/v1/about", &fx.admin).await;
        assert_eq!(about["scanners"]["trivy"]["downloaded_version"], "v0.76.5");
        fx.finish().await;
    }
}
