// Module placeholder. Filled in by later issues.

#[allow(dead_code)] // Used by the account routes.
pub mod account;
pub mod audit;
#[allow(dead_code)] // Used by the setup and login routes.
pub mod auth;
#[allow(dead_code)] // Used by the credential routes.
pub mod credential_probe;
pub mod credentials;
#[allow(dead_code)] // Used by the admin routes and the auth paths added in later issues.
pub mod ids;
#[allow(dead_code)] // The list routes that use this are added with the admin routes.
pub mod pagination;
#[allow(dead_code)] // Used by the session extractor and logout routes.
pub mod sessions;
#[allow(dead_code)] // Used by the login service.
pub mod throttle;
#[allow(dead_code)] // Used by the user response shape.
pub mod time;
#[allow(dead_code)] // Used by the admin user routes.
pub mod users;

#[allow(dead_code)] // The Harbor, OIDC, and alert clients are built in later issues.
pub mod oidc;
pub mod oidc_jwt;
pub mod oidc_settings;
#[cfg(test)]
pub mod oidc_test_support;
pub mod outbound;
