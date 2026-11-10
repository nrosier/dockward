//! The operator-configurable limits of the store (`specs/spinoff-local-scan.md`, section 13;
//! decisions 18 and 19).
//!
//! Values are `system_config` keys. A missing or unusable key falls back to the decision default,
//! and every value is stored and read in bytes. The defaults read as MiB and GiB.

use std::path::Path;

use crate::error::AppError;
use crate::services::registry::transport::disk_guard;

/// `images.max_stored`: the most stored images before eviction (decision 18).
pub const MAX_STORED_KEY: &str = "images.max_stored";
/// `pull.max_bytes_per_image`: the byte cap for one image (decision 19).
pub const PULL_CAP_KEY: &str = "pull.max_bytes_per_image";
/// `disk.min_free_bytes_before_pull`: the free space a pull needs first (decision 19).
pub const MIN_FREE_KEY: &str = "disk.min_free_bytes_before_pull";

/// Default stored images (decision 18).
pub const DEFAULT_MAX_STORED: i64 = 20;
/// Default pull cap: 10 GiB per image (decision 19; the larger reading).
pub const DEFAULT_PULL_CAP_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Default free disk before a pull: 10 GiB (decision 19; the larger reading).
pub const DEFAULT_MIN_FREE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// The store's limits, read once per job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreLimits {
    pub max_stored: i64,
    pub pull_cap_bytes: u64,
    pub min_free_bytes: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_stored: DEFAULT_MAX_STORED,
            pull_cap_bytes: DEFAULT_PULL_CAP_BYTES,
            min_free_bytes: DEFAULT_MIN_FREE_BYTES,
        }
    }
}

/// Parses a stored limit. `None` (unset), an empty value, zero or a non-number all give the
/// default, so a bad row cannot disable the cap or the disk guard.
pub fn parse_positive_u64(value: Option<&str>, default: u64) -> u64 {
    value
        .map(str::trim)
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Parses `images.max_stored`. Only a positive integer is kept; anything else is the default.
pub fn parse_max_stored(value: Option<&str>) -> i64 {
    value
        .map(str::trim)
        .and_then(|text| text.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_STORED)
}

/// The byte cap check on the declared size, before any byte is downloaded. A declared size over
/// the cap is `ImageTooLarge`. The streamed count is checked against the same cap by the
/// registry client.
pub fn check_declared_size(declared: u64, cap: u64) -> Result<(), AppError> {
    if declared > cap {
        Err(AppError::ImageTooLarge)
    } else {
        Ok(())
    }
}

/// The free-disk guard before a pull. `free_bytes` is the free space of the store volume, read
/// by the caller with [`free_bytes_at`]. Below the minimum is `InsufficientDisk`.
pub fn check_free_disk(free_bytes: u64, min_free_bytes: u64) -> Result<(), AppError> {
    disk_guard(free_bytes, min_free_bytes)
}

/// The free space available to an unprivileged caller on the volume that holds `path`, in bytes.
/// Uses `statvfs`. A path that cannot be read is an internal error, and the caller fails the job
/// with the fixed text, never the path.
pub fn free_bytes_at(path: &Path) -> Result<u64, AppError> {
    let stat = rustix::fs::statvfs(path).map_err(|_| AppError::InternalError)?;
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or(AppError::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_decision_values() {
        let limits = StoreLimits::default();
        assert_eq!(limits.max_stored, 20);
        assert_eq!(limits.pull_cap_bytes, 10 * 1024 * 1024 * 1024);
        assert_eq!(limits.min_free_bytes, 10 * 1024 * 1024 * 1024);
    }

    #[test]
    fn bad_limit_values_fall_back_to_the_default() {
        assert_eq!(parse_max_stored(None), 20);
        assert_eq!(parse_max_stored(Some("0")), 20);
        assert_eq!(parse_max_stored(Some("-3")), 20);
        assert_eq!(parse_max_stored(Some("many")), 20);
        assert_eq!(parse_max_stored(Some(" 7 ")), 7);
        assert_eq!(parse_positive_u64(Some("0"), 9), 9);
        assert_eq!(parse_positive_u64(Some("12"), 9), 12);
    }

    #[test]
    fn declared_size_over_the_cap_is_refused() {
        assert!(check_declared_size(100, 100).is_ok());
        assert_eq!(check_declared_size(101, 100), Err(AppError::ImageTooLarge));
    }

    #[test]
    fn free_disk_below_the_minimum_is_refused() {
        assert!(check_free_disk(10, 10).is_ok());
        assert_eq!(check_free_disk(9, 10), Err(AppError::InsufficientDisk));
    }

    #[test]
    fn free_bytes_of_a_real_volume_is_readable() {
        assert!(free_bytes_at(&std::env::temp_dir()).is_ok());
    }
}
