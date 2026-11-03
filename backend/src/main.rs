use axum::{http::StatusCode, routing::get, Router};
use tokio::net::TcpListener;

mod config;

const BIND_ADDR: &str = "0.0.0.0:8080";

async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok")
}

fn app() -> Router {
    Router::new().route("/healthz", get(healthz))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Refuse to start without a valid key. This runs before the port is bound.
    let _encryption_key = config::load_encryption_key()?;
    let listener = TcpListener::bind(BIND_ADDR).await?;
    axum::serve(listener, app()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let (status, body) = healthz().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }
}
