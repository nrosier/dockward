//! Admin scan settings (`specs/spinoff-local-scan.md`, section 13; decisions 18 and 19). They are
//! `system_config` values, so a change applies without a restart. Values are stored in bytes.
//! A missing or unusable stored value reads as the decision default.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::config;
use crate::error::AppError;
use crate::services::audit::{self, Actor};
use crate::services::scan::{OUTPUT_MAX_KEY, TIMEOUT_KEY};
use crate::services::scanner::process::{DEFAULT_OUTPUT_MAX_BYTES, DEFAULT_TIMEOUT};
use crate::services::storage::limits::{
    DEFAULT_MIN_FREE_BYTES, DEFAULT_PULL_CAP_BYTES, MAX_STORED_KEY, MIN_FREE_KEY, PULL_CAP_KEY,
    parse_max_stored, parse_positive_u64,
};

const SCANNERS_KEY: &str = "scanners.enabled";
const SCANNERS: [&str; 2] = ["grype", "trivy"];

/// Decided (spec author): bounds, because the spec names none. Each keeps a typo from turning a
/// limit off or setting one that cannot work.
pub const MAX_STORED_RANGE: (i64, i64) = (1, 10_000);
pub const TIMEOUT_RANGE: (u64, u64) = (10, 86_400);
pub const OUTPUT_RANGE: (u64, u64) = (1024 * 1024, 4 * 1024 * 1024 * 1024);
pub const PULL_CAP_RANGE: (u64, u64) = (1024 * 1024, 1024 * 1024 * 1024 * 1024);
pub const MIN_FREE_RANGE: (u64, u64) = (0, 1024 * 1024 * 1024 * 1024);

/// The settings object, in the field names of the route table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSettings {
    pub max_stored: i64,
    pub scanners_enabled: Vec<String>,
    pub scanner_timeout_s: u64,
    pub scanner_output_max_bytes: u64,
    pub pull_cap_bytes: u64,
    pub min_free_disk_bytes: u64,
}

impl ScanSettings {
    fn pairs(&self) -> [(&'static str, String); 6] {
        [
            (MAX_STORED_KEY, self.max_stored.to_string()),
            (SCANNERS_KEY, self.scanners_enabled.join(",")),
            (TIMEOUT_KEY, self.scanner_timeout_s.to_string()),
            (OUTPUT_MAX_KEY, self.scanner_output_max_bytes.to_string()),
            (PULL_CAP_KEY, self.pull_cap_bytes.to_string()),
            (MIN_FREE_KEY, self.min_free_disk_bytes.to_string()),
        ]
    }
}

fn enabled_from(value: Option<&str>) -> Vec<String> {
    let listed: Vec<String> = value
        .unwrap_or_default()
        .split(',')
        .map(|word| word.trim().to_ascii_lowercase())
        .filter(|word| SCANNERS.contains(&word.as_str()))
        .collect();
    if listed.is_empty() {
        SCANNERS.iter().map(|word| (*word).to_owned()).collect()
    } else {
        listed
    }
}

/// Reads the settings, with the defaults for what is unset.
pub async fn read(pool: &SqlitePool) -> Result<ScanSettings, AppError> {
    let max_stored = config::get(pool, MAX_STORED_KEY).await?;
    let enabled = config::get(pool, SCANNERS_KEY).await?;
    let timeout = config::get(pool, TIMEOUT_KEY).await?;
    let output = config::get(pool, OUTPUT_MAX_KEY).await?;
    let cap = config::get(pool, PULL_CAP_KEY).await?;
    let free = config::get(pool, MIN_FREE_KEY).await?;
    Ok(ScanSettings {
        max_stored: parse_max_stored(max_stored.as_deref()),
        scanners_enabled: enabled_from(enabled.as_deref()),
        scanner_timeout_s: parse_positive_u64(timeout.as_deref(), DEFAULT_TIMEOUT.as_secs()),
        scanner_output_max_bytes: parse_positive_u64(output.as_deref(), DEFAULT_OUTPUT_MAX_BYTES),
        pull_cap_bytes: parse_positive_u64(cap.as_deref(), DEFAULT_PULL_CAP_BYTES),
        min_free_disk_bytes: parse_positive_u64(free.as_deref(), DEFAULT_MIN_FREE_BYTES),
    })
}

fn out_of_range(name: &str) -> AppError {
    AppError::ValidationFailed(format!("{name} is outside the allowed range."))
}

/// Checks a new settings object. Any violation is `422`.
pub fn validate(settings: &ScanSettings) -> Result<(), AppError> {
    if !(MAX_STORED_RANGE.0..=MAX_STORED_RANGE.1).contains(&settings.max_stored) {
        return Err(out_of_range("max_stored"));
    }
    let checks = [
        (
            "scanner_timeout_s",
            settings.scanner_timeout_s,
            TIMEOUT_RANGE,
        ),
        (
            "scanner_output_max_bytes",
            settings.scanner_output_max_bytes,
            OUTPUT_RANGE,
        ),
        ("pull_cap_bytes", settings.pull_cap_bytes, PULL_CAP_RANGE),
        (
            "min_free_disk_bytes",
            settings.min_free_disk_bytes,
            MIN_FREE_RANGE,
        ),
    ];
    for (name, value, (low, high)) in checks {
        if !(low..=high).contains(&value) {
            return Err(out_of_range(name));
        }
    }
    let enabled = &settings.scanners_enabled;
    if enabled.is_empty()
        || enabled
            .iter()
            .any(|word| !SCANNERS.contains(&word.as_str()))
    {
        return Err(AppError::ValidationFailed(
            "scanners_enabled must list grype, trivy or both.".to_owned(),
        ));
    }
    Ok(())
}

/// Saves the settings and writes `settings.change` with the old and new values, in one
/// transaction. The scanners are stored once each, in the fixed order.
pub async fn write(
    pool: &SqlitePool,
    actor: &Actor,
    mut next: ScanSettings,
) -> Result<ScanSettings, AppError> {
    validate(&next)?;
    next.scanners_enabled = SCANNERS
        .iter()
        .filter(|word| next.scanners_enabled.iter().any(|have| have == *word))
        .map(|word| (*word).to_owned())
        .collect();
    let old = read(pool).await?;
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| AppError::InternalError)?;
    for (key, value) in next.pairs() {
        config::upsert(&mut tx, key, &value, false).await?;
    }
    audit::record(
        &mut tx,
        actor,
        "settings.change",
        "scan_settings",
        Some(&serde_json::json!({ "old": old, "new": next })),
    )
    .await?;
    tx.commit().await.map_err(|_| AppError::InternalError)?;
    Ok(next)
}
