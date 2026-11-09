//! Command-line subcommands. `harborgate` with no arguments serves; `restore <file>`
//! and `rotate-key` are offline commands run with the app stopped. See
//! `specs/security.md` (Backup and restore, Key rotation). `healthcheck` probes the
//! running server for the container healthcheck (`specs/deployment.md`, Health).

use std::path::PathBuf;
use std::time::Duration;

use crate::error::AppError;

/// The URL `harborgate healthcheck` probes: the liveness endpoint on the loopback
/// address and the port the server binds (`BIND_ADDR` in `main.rs`).
pub const HEALTHCHECK_URL: &str = "http://127.0.0.1:8080/healthz";

/// The probe gives up after this long, matching the 3-second healthcheck timeout.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// What the binary was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the web server and worker.
    Serve,
    /// Replace the database from a verified backup file.
    Restore(PathBuf),
    /// Re-encrypt stored credentials under a new key (#41).
    RotateKey,
    /// Probe the local server's `/healthz` and exit 0 only on `200` (#269).
    Healthcheck,
}

/// The text printed when the arguments are not understood.
pub const USAGE: &str = "usage:
  harborgate                  run the server
  harborgate restore <file>   replace the database from a backup (stop the app first)
  harborgate rotate-key       re-encrypt stored credentials under a new key (stop the app first)
  harborgate healthcheck      exit 0 if the running server answers /healthz with 200";

/// Reads the arguments after the program name. No arguments means `Serve`. Anything
/// that is not a known command, or a known command with the wrong arguments, returns
/// the usage text.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let Some((command, rest)) = args.split_first() else {
        return Ok(Command::Serve);
    };
    match (command.as_str(), rest) {
        ("restore", [file]) => Ok(Command::Restore(PathBuf::from(file))),
        ("restore", _) => Err(format!("restore needs exactly one backup file.\n{USAGE}")),
        ("rotate-key", []) => Ok(Command::RotateKey),
        ("healthcheck", []) => Ok(Command::Healthcheck),
        _ => Err(USAGE.to_owned()),
    }
}

/// Sends `GET url` and succeeds only on a `200` response. It reads no configuration,
/// opens no database and sends no credentials. Proxies from the environment are
/// ignored and redirects are not followed, so the probe reaches only `url`.
pub async fn healthcheck(url: &str) -> Result<(), AppError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HEALTHCHECK_TIMEOUT)
        .build()
        .map_err(|_| AppError::InternalError)?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| AppError::UpstreamUnreachable)?;
    if response.status() == reqwest::StatusCode::OK {
        Ok(())
    } else {
        Err(AppError::UpstreamUnreachable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn no_args_is_serve() {
        assert_eq!(parse(&[]), Ok(Command::Serve));
    }

    #[test]
    fn restore_takes_one_file() {
        assert_eq!(
            parse(&args(&["restore", "/data/backups/x.hgbk"])),
            Ok(Command::Restore(PathBuf::from("/data/backups/x.hgbk")))
        );
    }

    #[test]
    fn restore_needs_a_file() {
        let missing = parse(&args(&["restore"]));
        assert!(matches!(&missing, Err(text) if text.contains("restore needs")));
        let extra = parse(&args(&["restore", "a", "b"]));
        assert!(extra.is_err(), "two files were accepted");
    }

    #[test]
    fn rotate_key_is_recognised() {
        assert_eq!(parse(&args(&["rotate-key"])), Ok(Command::RotateKey));
    }

    #[test]
    fn healthcheck_is_recognised() {
        assert_eq!(parse(&args(&["healthcheck"])), Ok(Command::Healthcheck));
        assert!(parse(&args(&["healthcheck", "extra"])).is_err());
    }

    /// Serves `router` on an ephemeral loopback port and returns its `/healthz` URL.
    async fn serve(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}/healthz")
    }

    #[tokio::test]
    async fn healthcheck_passes_against_a_running_server() {
        let url =
            serve(axum::Router::new().route("/healthz", axum::routing::get(crate::healthz))).await;
        assert!(healthcheck(&url).await.is_ok());
    }

    #[tokio::test]
    async fn healthcheck_fails_on_a_non_200_response() {
        let router = axum::Router::new().route(
            "/healthz",
            axum::routing::get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
        );
        let url = serve(router).await;
        assert!(matches!(
            healthcheck(&url).await,
            Err(AppError::UpstreamUnreachable)
        ));
    }

    #[tokio::test]
    async fn healthcheck_does_not_follow_a_redirect() {
        let router = axum::Router::new().route(
            "/healthz",
            axum::routing::get(|| async { axum::response::Redirect::temporary("/ok") }),
        );
        let url = serve(router).await;
        assert!(healthcheck(&url).await.is_err());
    }

    #[tokio::test]
    async fn healthcheck_fails_when_nothing_listens() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://{addr}/healthz");
        assert!(matches!(
            healthcheck(&url).await,
            Err(AppError::UpstreamUnreachable)
        ));
    }

    #[test]
    fn healthcheck_probes_the_bind_port_on_loopback() {
        let port = crate::BIND_ADDR.rsplit(':').next().unwrap();
        assert_eq!(HEALTHCHECK_URL, format!("http://127.0.0.1:{port}/healthz"));
    }

    #[test]
    fn unknown_command_prints_usage() {
        assert_eq!(parse(&args(&["frobnicate"])), Err(USAGE.to_owned()));
    }
}
