//! The OCI layout writer (`specs/spinoff-local-scan.md`, section 4).
//!
//! A layout is `oci-layout`, `index.json` and `blobs/sha256/<hex>`. One stored image is one
//! platform manifest and its blobs. The writer receives blob bytes from the registry client as
//! a stream ([`crate::services::registry::transport::BlobSink`]); it does not fetch anything.
//!
//! The writer never trusts a registry string for a path. Each blob's file name is its verified
//! digest hex, and the manifest's own digest is computed here, so the layout names what it holds.
//!
//! The blob bytes are verified by the registry client while they stream, against the descriptor.
//! This module checks the same rule on the bytes it writes, so a layout whose files do not match
//! their names cannot be finalised.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::services::registry::transport::{BlobSink, sha256_digest_text};

/// The `oci-layout` file content, from the OCI image layout specification.
pub const OCI_LAYOUT_JSON: &str = r#"{"imageLayoutVersion":"1.0.0"}"#;

/// The `blobs/sha256` directory, relative to the layout root.
pub const BLOBS_SHA256: &str = "blobs/sha256";

/// The hex part of a `sha256:<hex>` digest, or an error when the text is not one.
fn digest_hex(digest: &str) -> Result<&str, AppError> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or(AppError::UpstreamContentInvalid)?;
    if hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(hex)
    } else {
        Err(AppError::UpstreamContentInvalid)
    }
}

/// Writes one layout into a temporary directory. Created by [`LayoutWriter::create`], then the
/// blobs and the manifest are added, then [`LayoutWriter::finish`] writes the index and returns
/// the layout path. A writer dropped before `finish` leaves its directory for the caller to
/// remove; the pull job does that.
pub struct LayoutWriter {
    dir: PathBuf,
    /// The manifest added with [`LayoutWriter::put_manifest`], as its digest and media type.
    manifest: Option<(String, String)>,
}

impl LayoutWriter {
    /// Creates the layout directories under `dir`. `dir` must not exist yet, so a stale
    /// directory from an earlier pull is never reused.
    pub fn create(dir: &Path) -> Result<Self, AppError> {
        if dir.exists() {
            return Err(AppError::InternalError);
        }
        fs::create_dir_all(dir.join(BLOBS_SHA256)).map_err(|_| AppError::InternalError)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            manifest: None,
        })
    }

    /// The directory of the layout being written.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Opens the blob file for `digest`. Its name is the digest hex, so the name is always a
    /// verified digest and never a registry string.
    pub fn blob_sink(&self, digest: &str) -> Result<BlobFile, AppError> {
        let hex = digest_hex(digest)?;
        let path = self.dir.join(BLOBS_SHA256).join(hex);
        let file = fs::File::create(&path).map_err(|_| AppError::InternalError)?;
        Ok(BlobFile {
            file,
            hasher: Sha256::new(),
            written: 0,
        })
    }

    /// Writes a manifest blob (the bytes the registry sent) into the layout. Its digest is
    /// computed from the bytes, and the layout's `index.json` names that digest.
    pub fn put_manifest(&mut self, bytes: &[u8], media_type: &str) -> Result<String, AppError> {
        let digest = sha256_digest_text(&Sha256::digest(bytes));
        let hex = digest_hex(&digest)?;
        let path = self.dir.join(BLOBS_SHA256).join(hex);
        write_new_file(&path, bytes)?;
        self.manifest = Some((digest.clone(), media_type.to_owned()));
        Ok(digest)
    }

    /// Writes `oci-layout` and `index.json` and returns the layout directory. The index lists
    /// exactly one descriptor: the platform manifest. Fails if no manifest was added.
    pub fn finish(self) -> Result<PathBuf, AppError> {
        let Some((digest, media_type)) = self.manifest.clone() else {
            return Err(AppError::InternalError);
        };
        let manifest_size = fs::metadata(self.dir.join(BLOBS_SHA256).join(digest_hex(&digest)?))
            .map_err(|_| AppError::InternalError)?
            .len();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "mediaType": media_type,
                "digest": digest,
                "size": manifest_size,
            }],
        });
        let index_text = serde_json::to_vec(&index).map_err(|_| AppError::InternalError)?;
        write_new_file(&self.dir.join("oci-layout"), OCI_LAYOUT_JSON.as_bytes())?;
        write_new_file(&self.dir.join("index.json"), &index_text)?;
        Ok(self.dir)
    }
}

/// A blob file being written. It hashes what it writes, and [`BlobFile::verify`] checks the hash
/// against the descriptor digest before the caller counts the blob as stored.
pub struct BlobFile {
    file: fs::File,
    hasher: Sha256,
    written: u64,
}

impl BlobFile {
    /// Checks the bytes written so far against `digest`, syncs the file and returns the byte
    /// count. A mismatch is `UpstreamContentInvalid`, and the caller removes the directory.
    pub fn verify(mut self, digest: &str) -> Result<u64, AppError> {
        let actual = sha256_digest_text(&self.hasher.finalize_reset());
        if actual != digest {
            return Err(AppError::UpstreamContentInvalid);
        }
        self.file.flush().map_err(|_| AppError::InternalError)?;
        self.file.sync_all().map_err(|_| AppError::InternalError)?;
        Ok(self.written)
    }
}

impl BlobSink for BlobFile {
    fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), AppError> {
        self.hasher.update(chunk);
        self.file
            .write_all(chunk)
            .map_err(|_| AppError::InternalError)?;
        self.written = self.written.saturating_add(chunk.len() as u64);
        Ok(())
    }
}

/// Creates a new file and writes `bytes`. Fails when the file already exists.
fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| AppError::InternalError)?;
    file.write_all(bytes).map_err(|_| AppError::InternalError)?;
    file.sync_all().map_err(|_| AppError::InternalError)
}
