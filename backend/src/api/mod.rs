#[allow(dead_code)] // The admin routes are mounted by the app router.
pub mod admin;
#[allow(dead_code)] // The extractor and logout routes are mounted by the app router.
pub mod auth;
pub mod credentials;
pub mod cves;
pub mod dashboard;
pub mod github_url;
#[allow(dead_code)] // The limiter and client IP are attached to routes in later issues.
pub mod hardening;
pub mod hubs;
#[allow(dead_code)] // The job routes are mounted by the app router.
pub mod jobs;
pub mod json;
#[allow(dead_code)] // The OIDC routes are mounted by the app router.
pub mod oidc;
#[cfg(test)]
mod route_tests;
pub mod scan;
pub mod scan_settings;
pub mod sources;
#[allow(dead_code)] // Shared by the extractor and the routes.
pub mod state;
pub mod static_files;
pub mod tag_actions;
pub mod totp;
