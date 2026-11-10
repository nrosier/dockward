//! The OCI layout store (`specs/spinoff-local-scan.md`, sections 4 and 13; decisions 2, 9, 18
//! and 19).
//!
//! A pull writes its blobs into `images/.tmp/<id>`, verifies each one by SHA-256 while streaming,
//! writes the layout files, and renames the directory to `images/<id>` only when every blob has
//! verified. A failed pull removes its temporary directory, so no final directory exists for an
//! image whose content did not verify.
//!
//! The blobs come from the registry client ([`crate::services::registry`]). This module does not
//! speak HTTP. The database work goes through [`StoreRepository`], so the storage rules can be
//! tested against a temporary SQLite database.

pub mod eviction;
pub mod job;
pub mod layout;
pub mod limits;
pub mod pull;
pub mod repository;
pub mod startup;

#[cfg(test)]
mod job_tests;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use crate::error::AppError;

/// Accepts only a generated id: 32 lowercase hex characters (`services/ids.rs`). A directory
/// name is never built from anything else, so no registry string can reach a path.
pub fn checked_id(id: &str) -> Result<&str, AppError> {
    if id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(id)
    } else {
        Err(AppError::InternalError)
    }
}

/// The directory under the data directory that holds stored layouts (`images`).
pub const IMAGES_DIR: &str = "images";
/// The temporary directory for a pull in progress (`images/.tmp`).
pub const TMP_DIR: &str = ".tmp";

/// The root of the store: `<data dir>/images`. Every layout and temporary directory is a child of
/// it, and every path is built from a generated id, never from a registry string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRoot {
    root: PathBuf,
}

impl StoreRoot {
    /// The store under `data_dir`, as `<data_dir>/images`.
    pub fn under(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join(IMAGES_DIR),
        }
    }

    /// A store rooted at `root` itself. Used by the tests and by callers that place the store
    /// elsewhere.
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// The `images` directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The temporary directory of one pull: `images/.tmp/<id>`. Refused unless `id` is a
    /// generated id (32 lowercase hex characters).
    pub fn tmp_dir(&self, id: &str) -> Result<PathBuf, AppError> {
        Ok(self.root.join(TMP_DIR).join(checked_id(id)?))
    }

    /// The final layout directory of one stored image: `images/<id>`. Refused unless `id` is a
    /// generated id.
    pub fn layout_dir(&self, id: &str) -> Result<PathBuf, AppError> {
        Ok(self.root.join(checked_id(id)?))
    }

    /// The `.tmp` directory itself.
    pub fn tmp_root(&self) -> PathBuf {
        self.root.join(TMP_DIR)
    }
}

/// The fixed `last_error` and error texts of the store (`specs/spinoff-local-scan.md`, section 6).
/// These strings are the only ones a job, an alert or a log line carries.
pub mod messages {
    /// Free disk below the minimum before a pull.
    pub const NOT_ENOUGH_DISK: &str = "not enough disk space";
    /// A pull over the per-image cap.
    pub const IMAGE_TOO_LARGE: &str = "image is larger than the allowed size";
    /// A blob or manifest digest did not match.
    pub const DIGEST_MISMATCH: &str = "image content did not match its digest";
    /// A layout evicted before a scan could start.
    pub const NO_LONGER_STORED: &str = "image is no longer stored";
}
