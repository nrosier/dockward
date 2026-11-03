//! The Harbor robot test. `GET /api/v2.0/users/current` answers `412` for a robot
//! account, `401` for a wrong, disabled, or expired robot, and `200` for a human
//! account (which is rejected). Sources: `specs/integrations.md` (Test button),
//! `specs/api.md` (Credentials, Test button).
//!
//! Every request goes through [`OutboundClient`], so the address check applies.

use reqwest::Url;

use crate::error::AppError;
use crate::services::outbound::{self, OutboundClient, TargetClass};

/// One check in the test response: `{"name","ok","detail"}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// The status a probe got back. The request itself is the only network effect.
#[allow(async_fn_in_trait)]
pub trait HarborProbe {
    /// Sends the robot test and returns the HTTP status code.
    async fn users_current(
        &self,
        base: &Url,
        username: &str,
        secret: &[u8],
    ) -> Result<u16, AppError>;
}

/// Production probe: the guarded client, HTTP Basic with the robot credential.
pub struct OutboundHarborProbe {
    client: OutboundClient,
}

impl OutboundHarborProbe {
    pub fn new(allow_private: bool) -> Result<Self, AppError> {
        let client = outbound::client(TargetClass::Harbor, allow_private)
            .map_err(|_| AppError::InternalError)?;
        Ok(Self { client })
    }
}

impl HarborProbe for OutboundHarborProbe {
    async fn users_current(
        &self,
        base: &Url,
        username: &str,
        secret: &[u8],
    ) -> Result<u16, AppError> {
        let url = base
            .join("api/v2.0/users/current")
            .map_err(|_| AppError::InternalError)?;
        let secret = std::str::from_utf8(secret).map_err(|_| AppError::InternalError)?;
        let response = self
            .client
            .get(&url)
            .map_err(|_| AppError::UpstreamUnreachable)?
            .basic_auth(username, Some(secret))
            .send()
            .await
            .map_err(|_| AppError::UpstreamUnreachable)?;
        Ok(response.status().as_u16())
    }
}

/// Maps the `users/current` status to the test result. Only `412` passes.
pub fn harbor_check(status: u16) -> Check {
    let (ok, detail) = match status {
        412 => (true, "the robot account credential works".to_owned()),
        401 => (
            false,
            "the robot secret is wrong, or the robot is disabled or expired".to_owned(),
        ),
        200 => (
            false,
            "the credentials belong to a human account; only robot accounts are accepted"
                .to_owned(),
        ),
        other => (false, format!("unexpected status {other} from Harbor")),
    };
    Check {
        name: "harbor_robot",
        ok,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_412_passes() {
        assert!(harbor_check(412).ok);
        assert!(!harbor_check(401).ok);
        assert!(!harbor_check(200).ok);
        assert!(!harbor_check(500).ok);
    }

    #[test]
    fn human_account_is_rejected_with_a_reason() {
        let check = harbor_check(200);
        assert_eq!(check.name, "harbor_robot");
        assert!(check.detail.contains("human account"));
    }
}
