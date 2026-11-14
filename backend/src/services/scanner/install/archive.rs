//! The checksums file and the release archive (#403).
//!
//! The checksums file is the GoReleaser format, one `<sha256 hex>  <file name>` per line. The
//! archive is a gzip tar; only the one entry named like the scanner (`trivy`, `grype`, at the top
//! level) is written, and nothing else in the archive ever reaches the disk. An entry whose path
//! is absolute or holds `..` refuses the whole archive.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};

/// Why an archive was refused. Logged as the fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFault {
    /// An entry path is absolute or climbs out with `..`.
    PathTraversal,
    /// The scanner binary is not a regular file, or appears twice.
    BadBinaryEntry,
    /// No entry is the scanner binary.
    MissingBinary,
    /// The binary is larger than the cap.
    TooLarge,
    /// The archive could not be read.
    Unreadable,
    /// The binary could not be written.
    Write,
}

impl ArchiveFault {
    pub fn text(self) -> &'static str {
        match self {
            ArchiveFault::PathTraversal => "path_traversal",
            ArchiveFault::BadBinaryEntry => "bad_binary_entry",
            ArchiveFault::MissingBinary => "missing_binary",
            ArchiveFault::TooLarge => "binary_too_large",
            ArchiveFault::Unreadable => "unreadable",
            ArchiveFault::Write => "write_failed",
        }
    }
}

/// The SHA-256 the checksums file gives for `file_name`, as 32 bytes. `None` when there is no
/// line for it, a line is malformed, or two lines for it disagree.
pub fn expected_sha256(checksums: &[u8], file_name: &str) -> Option<[u8; 32]> {
    let text = std::str::from_utf8(checksums).ok()?;
    let mut found: Option<[u8; 32]> = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        // `sha256sum` marks binary mode with a leading `*`.
        if name.strip_prefix('*').unwrap_or(name) != file_name {
            continue;
        }
        let digest = parse_hex(hash)?;
        if found.is_some_and(|seen| seen != digest) {
            return None;
        }
        found = Some(digest);
    }
    found
}

fn parse_hex(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let (pairs, _) = bytes.as_chunks::<2>();
    let mut out = [0u8; 32];
    for (slot, [high, low]) in out.iter_mut().zip(pairs) {
        let high = (*high as char).to_digit(16)?;
        let low = (*low as char).to_digit(16)?;
        *slot = u8::try_from(high * 16 + low).ok()?;
    }
    Some(out)
}

/// True when `path` is the top-level entry `name` (an optional leading `./` is allowed).
fn is_top_level(path: &Path, name: &str) -> bool {
    let mut normal = path
        .components()
        .filter(|c| !matches!(c, Component::CurDir));
    matches!(
        (normal.next(), normal.next()),
        (Some(Component::Normal(first)), None) if first == name
    )
}

fn climbs_out(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

/// Extracts the top-level entry `binary` of the gzip tar `archive` to `dest`, with mode 0755.
/// At most `max_bytes` are written. Refuses the whole archive on any traversal entry. On an
/// error `dest` may be left partly written; the caller removes the folder.
pub fn extract_binary(
    archive: impl Read,
    binary: &str,
    dest: &Path,
    max_bytes: u64,
) -> Result<(), ArchiveFault> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let entries = tar.entries().map_err(|_| ArchiveFault::Unreadable)?;
    let mut written = false;
    for entry in entries {
        let mut entry = entry.map_err(|_| ArchiveFault::Unreadable)?;
        let path = entry
            .path()
            .map_err(|_| ArchiveFault::Unreadable)?
            .into_owned();
        if climbs_out(&path) {
            return Err(ArchiveFault::PathTraversal);
        }
        if let Some(link) = entry.link_name().map_err(|_| ArchiveFault::Unreadable)?
            && climbs_out(&link)
        {
            return Err(ArchiveFault::PathTraversal);
        }
        if !is_top_level(&path, binary) {
            continue;
        }
        if written || !entry.header().entry_type().is_file() {
            return Err(ArchiveFault::BadBinaryEntry);
        }
        if entry.size() > max_bytes {
            return Err(ArchiveFault::TooLarge);
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(dest)
            .map_err(|_| ArchiveFault::Write)?;
        let copied = std::io::copy(&mut (&mut entry).take(max_bytes + 1), &mut file)
            .map_err(|_| ArchiveFault::Unreadable)?;
        if copied > max_bytes {
            return Err(ArchiveFault::TooLarge);
        }
        file.flush().map_err(|_| ArchiveFault::Write)?;
        file.sync_all().map_err(|_| ArchiveFault::Write)?;
        written = true;
    }
    if written {
        Ok(())
    } else {
        Err(ArchiveFault::MissingBinary)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One tar entry for a fixture: a raw path (written as given, `..` included), the type and
    /// the body.
    pub(crate) struct Entry<'a> {
        pub path: &'a [u8],
        pub kind: tar::EntryType,
        pub body: &'a [u8],
    }

    pub(crate) fn file<'a>(path: &'a str, body: &'a [u8]) -> Entry<'a> {
        Entry {
            path: path.as_bytes(),
            kind: tar::EntryType::Regular,
            body,
        }
    }

    /// A gzip tar of `entries`. The raw name is set directly, so a traversal entry can be built.
    pub(crate) fn tar_gz(entries: &[Entry<'_>]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for entry in entries {
            let mut header = tar::Header::new_old();
            header.as_old_mut().name[..entry.path.len()].copy_from_slice(entry.path);
            header.set_entry_type(entry.kind);
            header.set_mode(0o644);
            header.set_size(entry.body.len() as u64);
            header.set_cksum();
            if let Err(err) = builder.append(&header, entry.body) {
                panic!("tar: {err}");
            }
        }
        let tar = match builder.into_inner() {
            Ok(tar) => tar,
            Err(err) => panic!("tar: {err}"),
        };
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        if let Err(err) = gz.write_all(&tar) {
            panic!("gz: {err}");
        }
        match gz.finish() {
            Ok(bytes) => bytes,
            Err(err) => panic!("gz: {err}"),
        }
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = crate::services::scanner::volume::tests::temp_data_dir(name);
        dir.join("out")
    }

    #[test]
    fn the_checksum_line_of_the_archive_is_found() {
        let sums = include_bytes!("fixtures/trivy_0.76.2_checksums.txt");
        let digest = expected_sha256(sums, "trivy_0.76.2_Linux-64bit.tar.gz");
        assert_eq!(
            digest.map(hex),
            Some("bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf".to_owned())
        );
        let grype = include_bytes!("fixtures/grype_0.121.3_checksums.txt");
        assert!(expected_sha256(grype, "grype_0.121.3_linux_amd64.tar.gz").is_some());
        assert_eq!(expected_sha256(sums, "trivy_0.76.2_Linux-64bit.tar"), None);
    }

    #[test]
    fn a_malformed_or_conflicting_checksum_is_no_answer() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert_eq!(expected_sha256(b"zz  x.tar.gz\n", "x.tar.gz"), None);
        assert_eq!(
            expected_sha256(
                format!("{a}  x.tar.gz\n{b}  x.tar.gz\n").as_bytes(),
                "x.tar.gz"
            ),
            None
        );
        assert!(expected_sha256(format!("{a} *x.tar.gz\n").as_bytes(), "x.tar.gz").is_some());
        assert_eq!(expected_sha256(&[0xff, 0xfe], "x.tar.gz"), None);
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn only_the_top_level_binary_is_written_with_the_executable_bit() {
        let dest = temp("extract-ok");
        let archive = tar_gz(&[
            file("LICENSE", b"text"),
            file("contrib/trivy", b"not this one"),
            file("./trivy", b"#!/bin/sh\n"),
        ]);
        assert_eq!(
            extract_binary(archive.as_slice(), "trivy", &dest, 1024),
            Ok(())
        );
        assert_eq!(std::fs::read(&dest).ok(), Some(b"#!/bin/sh\n".to_vec()));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dest).map(|m| m.permissions().mode() & 0o777);
        assert_eq!(mode.ok(), Some(0o755));
        assert!(!dest.with_file_name("LICENSE").exists());
    }

    #[test]
    fn a_path_traversal_entry_refuses_the_archive() {
        for bad in ["../trivy", "/etc/trivy", "a/../../trivy"] {
            let dest = temp("extract-traversal");
            let archive = tar_gz(&[file(bad, b"x"), file("trivy", b"bin")]);
            assert_eq!(
                extract_binary(archive.as_slice(), "trivy", &dest, 1024),
                Err(ArchiveFault::PathTraversal),
                "{bad}"
            );
            assert!(
                !dest.exists(),
                "{bad}: nothing is written before the refusal"
            );
        }
    }

    #[test]
    fn a_missing_oversize_duplicate_or_linked_binary_is_refused() {
        let cases: Vec<(Vec<u8>, ArchiveFault)> = vec![
            (
                tar_gz(&[file("README.md", b"x")]),
                ArchiveFault::MissingBinary,
            ),
            (tar_gz(&[file("grype", &[0u8; 64])]), ArchiveFault::TooLarge),
            (
                tar_gz(&[file("grype", b"a"), file("grype", b"b")]),
                ArchiveFault::BadBinaryEntry,
            ),
            (
                tar_gz(&[Entry {
                    path: b"grype",
                    kind: tar::EntryType::Symlink,
                    body: b"",
                }]),
                ArchiveFault::BadBinaryEntry,
            ),
            (b"not gzip".to_vec(), ArchiveFault::Unreadable),
        ];
        for (archive, fault) in cases {
            let dest = temp("extract-bad");
            assert_eq!(
                extract_binary(archive.as_slice(), "grype", &dest, 16),
                Err(fault)
            );
        }
    }
}
