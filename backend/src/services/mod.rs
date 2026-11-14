// Module placeholder. Filled in by later issues.

pub mod about;
pub mod acceptance;
#[allow(dead_code)] // Used by the account routes.
pub mod account;
pub mod advisory_lookup;
pub mod alert_channels;
#[allow(dead_code)] // The scan and publish steps raise alerts (Step 4+).
pub mod alert_send;
#[allow(dead_code)] // The scan and publish steps raise alerts (Step 4+).
pub mod alerts;
pub mod app_log;
pub mod audit;
#[allow(dead_code)] // Used by the setup and login routes.
pub mod auth;
pub mod backup;
#[allow(dead_code)] // Used by the credential routes.
pub mod credential_probe;
pub mod credentials;
pub mod cves;
pub mod dashboard;
pub mod discovery;
pub mod github_issues;
pub mod github_scanning;
#[allow(dead_code)] // Some accessors are used by the publish step only (Step 4+).
pub mod github_url;
pub mod health;
pub mod hubs;
#[allow(dead_code)] // Used by the admin routes and the auth paths added in later issues.
pub mod ids;
pub mod images;
pub mod issue_lifecycle;
pub mod issue_rekey;
pub mod job_log;
pub mod job_runs;
#[allow(dead_code)] // Used by the job worker and the retry route.
pub mod jobs;
pub mod key_rotation;
pub mod legacy_analyses;
pub mod merged_view;
#[allow(dead_code)] // The list routes that use this are added with the admin routes.
pub mod pagination;
pub mod publish;
#[allow(dead_code)] // The spinoff pull and discovery jobs call the registry client (Step 3+).
pub mod registry;
pub mod retention;
pub mod sarif;
pub mod scan;
pub mod scan_settings;
pub mod scanner;
#[allow(dead_code)] // Used by the session extractor and logout routes.
pub mod sessions;
pub mod source_credentials;
pub mod sources;
#[allow(dead_code)] // The pull and eviction jobs call the store (Steps 4 and 5).
pub mod storage;
pub mod tag_actions;
#[allow(dead_code)] // Used by the login service.
pub mod throttle;
#[allow(dead_code)] // Used by the user response shape.
pub mod time;
pub mod totp;
#[allow(dead_code)] // Used by the admin user routes.
pub mod users;

#[allow(dead_code)] // The Harbor, OIDC, and alert clients are built in later issues.
pub mod oidc;
pub mod oidc_jwt;
pub mod oidc_settings;
#[cfg(test)]
pub mod oidc_test_support;
#[allow(dead_code)] // The registry and pull steps use the rest of the guarded client (Step 3+).
pub mod outbound;
