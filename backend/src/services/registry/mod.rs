//! The OCI distribution client for the spinoff (`specs/spinoff-local-scan.md`, section 3;
//! decisions 2, 3, 11, 12 and 14).
//!
//! The client talks to a registry over `reqwest` and never to a Docker daemon. It supports the
//! `/v2/` challenge and Bearer token flow, manifest and image index fetch, tag listing with
//! `Link` paging, and blob streaming with SHA-256 verification against the descriptor.
//!
//! Credentials are passed in per call and are never stored in a field of the client. A token
//! is cached only as long as its expiry, inside a pull, and is never logged.

pub mod grammar;
pub mod manifest;
pub mod policy;
pub mod transport;
