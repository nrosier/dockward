#[allow(dead_code)] // The admin routes are mounted by the app router.
pub mod admin;
#[allow(dead_code)] // The extractor and logout routes are mounted by the app router.
pub mod auth;
pub mod credentials;
pub mod cves;
#[allow(dead_code)] // The limiter and client IP are attached to routes in later issues.
pub mod hardening;
pub mod mappings;
#[allow(dead_code)] // The OIDC routes are mounted by the app router.
pub mod oidc;
#[allow(dead_code)] // Shared by the extractor and the routes.
pub mod state;
#[allow(dead_code)] // The sync job routes are mounted by the app router.
pub mod sync_jobs;
#[allow(dead_code)] // The webhook route is mounted by the app router.
pub mod webhooks;
