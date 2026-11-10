// Module placeholder. Filled in by later issues.

pub mod acceptance;
#[allow(dead_code)] // Used by the account routes.
pub mod account;
pub mod alert_channels;
pub mod alert_send;
pub mod alerts;
pub mod app_log;
pub mod artifact_removal;
pub mod audit;
#[allow(dead_code)] // Used by the setup and login routes.
pub mod auth;
pub mod backup;
#[allow(dead_code)] // Used by the credential routes.
pub mod credential_probe;
pub mod credentials;
pub mod cves;
pub mod dashboard;
pub mod findings;
pub mod github_issues;
#[allow(dead_code)] // Used by the SARIF upload worker (#53).
pub mod github_scanning;
pub mod github_url;
#[allow(dead_code)] // Used by the sync pipeline.
pub mod harbor_client;
#[allow(dead_code)] // Used by the webhook route.
pub mod harbor_webhook;
pub mod health;
#[allow(dead_code)] // Used by the admin routes and the auth paths added in later issues.
pub mod ids;
pub mod issue_lifecycle;
pub mod job_runs;
pub mod key_rotation;
#[allow(dead_code)] // Used by the mapping routes.
pub mod mappings;
pub mod merged_view;
#[allow(dead_code)] // The list routes that use this are added with the admin routes.
pub mod pagination;
pub mod picker_upstream;
pub mod pickers;
pub mod poller;
pub mod project_webhooks;
#[allow(dead_code)] // The spinoff pull and discovery jobs call the registry client (Step 3+).
pub mod registry;
pub mod resolve;
pub mod retention;
#[allow(dead_code)] // Used by the sync pipeline.
pub mod sarif;
#[allow(dead_code)] // The spinoff scan and refresh jobs call the scanner runner (Step 4+).
pub mod scanner;
pub mod scanner_launch;
pub mod scanner_scan;
pub mod scanner_store;
pub mod scheduled_scan;
#[allow(dead_code)] // Used by the session extractor and logout routes.
pub mod sessions;
pub mod sync;
#[allow(dead_code)] // Used by the job worker and the retry route.
pub mod sync_jobs;
pub mod tag_scans;
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
