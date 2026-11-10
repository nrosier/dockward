use std::env::{self, VarError};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::{Zeroize, Zeroizing};

/// Prefix of every current environment variable.
const ENV_PREFIX: &str = "DOCKWARD_";
/// Prefix of the legacy names read as a fallback in release 0.2 only (decision 57).
const LEGACY_ENV_PREFIX: &str = "HARBORGATE_";

/// Reads a `DOCKWARD_*` variable from `lookup`. When it is unset, falls back to the matching
/// `HARBORGATE_*` name and logs a deprecation warning that names both variables and never
/// the value. `DOCKWARD_*` wins when both are set. Remove the fallback after release 0.2.
pub fn lookup_with_fallback<F>(lookup: &F, name: &str) -> Result<String, VarError>
where
    F: Fn(&str) -> Result<String, VarError>,
{
    match lookup(name) {
        Err(VarError::NotPresent) => {}
        other => return other,
    }
    let Some(rest) = name.strip_prefix(ENV_PREFIX) else {
        return Err(VarError::NotPresent);
    };
    let legacy = format!("{LEGACY_ENV_PREFIX}{rest}");
    let found = lookup(&legacy);
    if !matches!(found, Err(VarError::NotPresent)) {
        tracing::warn!(
            legacy = %legacy,
            current = %name,
            "{legacy} is deprecated and is read as a fallback in release 0.2 only; rename it to {name}"
        );
    }
    found
}

/// Reads a variable from the process environment, with the `HARBORGATE_*` fallback.
pub fn env_var(name: &str) -> Result<String, VarError> {
    lookup_with_fallback(&|n: &str| env::var(n), name)
}

/// Name of the environment variable that holds the base64-encoded 32-byte key.
pub const ENCRYPTION_KEY_VAR: &str = "DOCKWARD_ENCRYPTION_KEY";

/// Required length of the decoded encryption key in bytes (AES-256).
pub const ENCRYPTION_KEY_LEN: usize = 32;

/// Startup configuration errors. Messages name the variable and the expected
/// format, and never include the value that was supplied.
#[derive(Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing,
    NotUnicode,
    InvalidBase64,
    WrongLength {
        decoded_len: usize,
    },
    /// A required setting is absent.
    Required {
        var: &'static str,
    },
    /// A setting is present but invalid. `reason` is a fixed description and never
    /// contains the supplied value.
    Invalid {
        var: &'static str,
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Required { var } => write!(f, "{var} is required."),
            ConfigError::Invalid { var, reason } => write!(f, "{var} is invalid: {reason}."),
            ConfigError::Missing => write!(
                f,
                "{ENCRYPTION_KEY_VAR} is missing; set it to {ENCRYPTION_KEY_LEN} random bytes encoded in base64."
            ),
            ConfigError::NotUnicode => write!(
                f,
                "{ENCRYPTION_KEY_VAR} is not valid UTF-8; set it to {ENCRYPTION_KEY_LEN} random bytes encoded in base64."
            ),
            ConfigError::InvalidBase64 => write!(
                f,
                "{ENCRYPTION_KEY_VAR} is not valid base64 (standard alphabet); set it to {ENCRYPTION_KEY_LEN} random bytes encoded in base64."
            ),
            ConfigError::WrongLength { decoded_len } => write!(
                f,
                "{ENCRYPTION_KEY_VAR} must decode to exactly {ENCRYPTION_KEY_LEN} bytes, but decoded to {decoded_len} bytes; set it to {ENCRYPTION_KEY_LEN} random bytes encoded in base64."
            ),
        }
    }
}

// Debug matches Display so that returning this error from `main` prints only the message.
impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ConfigError {}

/// The 32-byte encryption key. It has no `Display` impl, and its `Debug` output is redacted.
#[allow(dead_code)] // Consumed by the encryption layer once it exists.
pub struct EncryptionKey([u8; ENCRYPTION_KEY_LEN]);

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl EncryptionKey {
    #[allow(dead_code)] // Consumed by the encryption layer once it exists.
    pub fn as_bytes(&self) -> &[u8; ENCRYPTION_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey(<redacted>)")
    }
}

/// Reads `DOCKWARD_ENCRYPTION_KEY` and returns the decoded 32-byte key.
pub fn load_encryption_key() -> Result<EncryptionKey, ConfigError> {
    load_encryption_key_with(env_var)
}

/// Same as [`load_encryption_key`], with the variable lookup injected for testing.
pub fn load_encryption_key_with<F>(lookup: F) -> Result<EncryptionKey, ConfigError>
where
    F: FnOnce(&str) -> Result<String, VarError>,
{
    let raw = match lookup(ENCRYPTION_KEY_VAR) {
        Ok(value) => Zeroizing::new(value),
        Err(VarError::NotPresent) => return Err(ConfigError::Missing),
        Err(VarError::NotUnicode(_)) => return Err(ConfigError::NotUnicode),
    };
    parse_encryption_key(raw.as_str())
}

/// Name of the environment variable that holds the key that wrote the current values.
/// Read only by the offline `rotate-key` command.
pub const OLD_ENCRYPTION_KEY_VAR: &str = "DOCKWARD_OLD_ENCRYPTION_KEY";

/// Reads `DOCKWARD_OLD_ENCRYPTION_KEY` the same way as the new key. Errors name this
/// variable and never include the value.
pub fn load_old_encryption_key() -> Result<EncryptionKey, ConfigError> {
    load_old_encryption_key_with(env_var)
}

/// Same as [`load_old_encryption_key`], with the variable lookup injected for testing.
pub fn load_old_encryption_key_with<F>(lookup: F) -> Result<EncryptionKey, ConfigError>
where
    F: FnOnce(&str) -> Result<String, VarError>,
{
    let raw = match lookup(OLD_ENCRYPTION_KEY_VAR) {
        Ok(value) => Zeroizing::new(value),
        Err(VarError::NotPresent) => {
            return Err(ConfigError::Required {
                var: OLD_ENCRYPTION_KEY_VAR,
            });
        }
        Err(VarError::NotUnicode(_)) => {
            return Err(ConfigError::Invalid {
                var: OLD_ENCRYPTION_KEY_VAR,
                reason: "is not valid UTF-8".to_owned(),
            });
        }
    };
    parse_encryption_key(raw.as_str()).map_err(|err| ConfigError::Invalid {
        var: OLD_ENCRYPTION_KEY_VAR,
        reason: match err {
            ConfigError::InvalidBase64 => "is not valid base64 (standard alphabet)".to_owned(),
            _ => format!("must be {ENCRYPTION_KEY_LEN} random bytes encoded in base64"),
        },
    })
}

/// Decodes a base64 (standard alphabet) string into an [`EncryptionKey`].
pub fn parse_encryption_key(encoded: &str) -> Result<EncryptionKey, ConfigError> {
    // The decode buffer holds key material, so it is zeroed on drop.
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded.trim())
            .map_err(|_| ConfigError::InvalidBase64)?,
    );
    let bytes: [u8; ENCRYPTION_KEY_LEN] =
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::WrongLength {
                decoded_len: decoded.len(),
            })?;
    Ok(EncryptionKey(bytes))
}

pub const PUBLIC_URL_VAR: &str = "DOCKWARD_PUBLIC_URL";
pub const TRUSTED_PROXIES_VAR: &str = "DOCKWARD_TRUSTED_PROXIES";
pub const DATA_DIR_VAR: &str = "DOCKWARD_DATA_DIR";
pub const BACKUP_DIR_VAR: &str = "DOCKWARD_BACKUP_DIR";
pub const ALLOW_PRIVATE_HARBOR_VAR: &str = "DOCKWARD_ALLOW_PRIVATE_HARBOR";
pub const ALLOW_PRIVATE_OIDC_VAR: &str = "DOCKWARD_ALLOW_PRIVATE_OIDC";
pub const ALLOW_PRIVATE_ALERTS_VAR: &str = "DOCKWARD_ALLOW_PRIVATE_ALERTS";

const DEFAULT_DATA_DIR: &str = "/data";
const DEFAULT_BACKUP_DIR: &str = "/data/backups";

/// Non-secret startup settings, validated before the port is bound.
#[allow(dead_code)] // Consumed by the database, HTTP, and outbound layers in later issues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub public_url: String,
    pub trusted_proxies: Vec<Cidr>,
    pub data_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub allow_private_harbor: bool,
    pub allow_private_oidc: bool,
    pub allow_private_alerts: bool,
}

/// An IPv4 or IPv6 network in CIDR notation. The stored address is the network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

#[allow(dead_code)] // `contains` is consumed by the client IP rule in a later issue.
impl Cidr {
    /// Parses `address/length`. Bare addresses, out-of-range lengths, and set host bits
    /// are rejected. The error text is a fixed description and never echoes the input.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let (address, length) = text
            .split_once('/')
            .ok_or("must be a CIDR such as 10.0.0.0/8")?;
        let network: IpAddr = address.parse().map_err(|_| "has an invalid IP address")?;
        if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
            return Err("has an invalid prefix length");
        }
        let prefix: u8 = length.parse().map_err(|_| "has an invalid prefix length")?;
        let max: u8 = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err("has a prefix length out of range");
        }
        if !is_network_address(network, prefix) {
            return Err("has host bits set; use the network address");
        }
        Ok(Self { network, prefix })
    }

    /// Whether `ip` falls inside this network. An IPv4 network never matches an IPv6 address.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                (u32::from(candidate) & mask_v4(self.prefix)) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                (u128::from(candidate) & mask_v6(self.prefix)) == u128::from(net)
            }
            _ => false,
        }
    }
}

fn mask_v4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0)
}

fn mask_v6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0)
}

fn is_network_address(addr: IpAddr, prefix: u8) -> bool {
    match addr {
        IpAddr::V4(a) => (u32::from(a) & !mask_v4(prefix)) == 0,
        IpAddr::V6(a) => (u128::from(a) & !mask_v6(prefix)) == 0,
    }
}

fn invalid(var: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        var,
        reason: reason.into(),
    }
}

/// Reads one variable. Returns `None` when it is unset.
fn read_var<F>(lookup: &F, var: &'static str) -> Result<Option<String>, ConfigError>
where
    F: Fn(&str) -> Result<String, VarError>,
{
    match lookup(var) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(invalid(var, "is not valid UTF-8")),
    }
}

/// Reads a boolean flag. Unset means `false`. Only `true` or `false` are accepted, in any case.
fn read_bool<F>(lookup: &F, var: &'static str) -> Result<bool, ConfigError>
where
    F: Fn(&str) -> Result<String, VarError>,
{
    match read_var(lookup, var)? {
        None => Ok(false),
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => Err(invalid(var, "must be true or false")),
    }
}

/// Reads a directory path, falling back to `default` when unset.
fn read_path<F>(lookup: &F, var: &'static str, default: &str) -> Result<PathBuf, ConfigError>
where
    F: Fn(&str) -> Result<String, VarError>,
{
    match read_var(lookup, var)? {
        None => Ok(PathBuf::from(default)),
        Some(value) if value.trim().is_empty() => Err(invalid(var, "must not be empty")),
        Some(value) => Ok(PathBuf::from(value)),
    }
}

/// Parses `DOCKWARD_TRUSTED_PROXIES`: a comma-separated CIDR list. Unset or blank means empty.
fn parse_trusted_proxies(raw: Option<String>) -> Result<Vec<Cidr>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .enumerate()
        .map(|(index, entry)| {
            Cidr::parse(entry.trim()).map_err(|reason| {
                invalid(TRUSTED_PROXIES_VAR, format!("entry {} {reason}", index + 1))
            })
        })
        .collect()
}

/// Checks `DOCKWARD_PUBLIC_URL` and returns its canonical origin: no trailing slash,
/// a lowercase host, and the scheme's default port removed. Browsers send `Origin` in
/// this form, so the login same-origin check compares against it (`specs/security.md`).
/// Accepts `https://<host>[:port]`, and `http://localhost[:port]` for development only.
fn validate_public_url(raw: &str) -> Result<String, &'static str> {
    const SHAPE: &str = "must be an https:// origin such as https://dockward.example.com, or http://localhost for development";
    let origin = raw.strip_suffix('/').unwrap_or(raw);
    if let Some(rest) = origin.strip_prefix("https://") {
        return if valid_host_and_port(rest) {
            Ok(canonical_origin("https", rest, 443))
        } else {
            Err(SHAPE)
        };
    }
    if let Some(rest) = origin.strip_prefix("http://") {
        let lowered = rest.to_ascii_lowercase();
        let is_localhost =
            lowered == "localhost" || lowered.strip_prefix("localhost:").is_some_and(valid_port);
        return if is_localhost {
            Ok(canonical_origin("http", rest, 80))
        } else {
            Err(SHAPE)
        };
    }
    Err(SHAPE)
}

/// Builds `scheme://host[:port]` with a lowercase host, and drops the port when it is
/// `default_port`. The caller has already validated `rest` as `host[:port]`.
fn canonical_origin(scheme: &str, rest: &str, default_port: u16) -> String {
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    let host = host.to_ascii_lowercase();
    match port.and_then(|text| text.parse::<u16>().ok()) {
        Some(value) if value != default_port => format!("{scheme}://{host}:{value}"),
        _ => format!("{scheme}://{host}"),
    }
}

fn valid_host_and_port(text: &str) -> bool {
    let (host, port) = match text.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (text, None),
    };
    valid_hostname(host) && port.is_none_or(valid_port)
}

fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && matches!(port.parse::<u16>(), Ok(value) if value != 0)
}

/// Loads and validates every non-key setting. Pure: it reads only the injected lookup
/// and touches no files. Startup uses [`load_settings`], which also prepares the data dir.
pub fn load_settings_with<F>(lookup: F) -> Result<Settings, ConfigError>
where
    F: Fn(&str) -> Result<String, VarError>,
{
    let public_url = match read_var(&lookup, PUBLIC_URL_VAR)? {
        Some(raw) => validate_public_url(&raw).map_err(|reason| invalid(PUBLIC_URL_VAR, reason))?,
        None => {
            return Err(ConfigError::Required {
                var: PUBLIC_URL_VAR,
            });
        }
    };
    let trusted_proxies = parse_trusted_proxies(read_var(&lookup, TRUSTED_PROXIES_VAR)?)?;
    Ok(Settings {
        public_url,
        trusted_proxies,
        data_dir: read_path(&lookup, DATA_DIR_VAR, DEFAULT_DATA_DIR)?,
        // Created by `prepare_backup_dir` when the app starts. A backup run checks it again.
        backup_dir: read_path(&lookup, BACKUP_DIR_VAR, DEFAULT_BACKUP_DIR)?,
        allow_private_harbor: read_bool(&lookup, ALLOW_PRIVATE_HARBOR_VAR)?,
        allow_private_oidc: read_bool(&lookup, ALLOW_PRIVATE_OIDC_VAR)?,
        allow_private_alerts: read_bool(&lookup, ALLOW_PRIVATE_ALERTS_VAR)?,
    })
}

/// Creates the data directory if missing and proves it is writable with a probe file.
pub fn prepare_data_dir(path: &Path) -> Result<(), ConfigError> {
    fs::create_dir_all(path).map_err(|err| {
        invalid(
            DATA_DIR_VAR,
            format!("could not be created ({:?})", err.kind()),
        )
    })?;
    let probe = path.join(format!(".dockward-startup-check-{}", std::process::id()));
    let not_writable =
        |err: std::io::Error| invalid(DATA_DIR_VAR, format!("is not writable ({:?})", err.kind()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(not_writable)?;
    fs::remove_file(&probe).map_err(not_writable)
}

/// Creates the backup directory with mode 0700 when it does not exist. A directory that
/// already exists is left alone, writable or not: its mode is never changed, and a
/// backup run reports an unwritable one on its own. Call after [`prepare_data_dir`].
pub fn prepare_backup_dir(path: &Path) -> Result<(), ConfigError> {
    if path.exists() {
        return Ok(());
    }
    let failed = |err: std::io::Error| {
        invalid(
            BACKUP_DIR_VAR,
            format!("could not be created ({:?})", err.kind()),
        )
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(failed)?;
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        // Created by someone else a moment ago: leave it alone.
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(err) => return Err(failed(err)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The creation mode is cut by the umask, never widened. Set it exactly.
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(failed)?;
    }
    Ok(())
}

/// Loads the settings from the process environment and prepares the data directory.
/// Call this before binding the port.
pub fn load_settings() -> Result<Settings, ConfigError> {
    let settings = load_settings_with(env_var)?;
    prepare_data_dir(&settings.data_dir)?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Base64 of 32 zero bytes. Test value only.
    const TEST_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn valid_32_byte_key_is_accepted() {
        let key = parse_encryption_key(TEST_KEY_B64);
        assert!(matches!(&key, Ok(k) if k.as_bytes() == &[0u8; 32]));
    }

    #[test]
    fn missing_variable_is_rejected() {
        let result = load_encryption_key_with(|_| Err(VarError::NotPresent));
        assert_eq!(result.err(), Some(ConfigError::Missing));
    }

    #[test]
    fn env_example_placeholder_is_rejected() {
        // The placeholder in .env.example must never start the app as-is.
        let result = parse_encryption_key("replace-with-openssl-rand-base64-32");
        assert!(
            result.is_err(),
            "the .env.example placeholder must be rejected"
        );
    }

    #[test]
    fn invalid_base64_is_rejected() {
        let result = parse_encryption_key("not base64!!");
        assert_eq!(result.err(), Some(ConfigError::InvalidBase64));
    }

    #[test]
    fn key_decoding_to_31_bytes_is_rejected() {
        // 31 zero bytes encoded as base64.
        let result = parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(
            result.err(),
            Some(ConfigError::WrongLength { decoded_len: 31 })
        );
    }

    #[test]
    fn key_decoding_to_33_bytes_is_rejected() {
        // 33 zero bytes encoded as base64.
        let result = parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(
            result.err(),
            Some(ConfigError::WrongLength { decoded_len: 33 })
        );
    }

    #[test]
    fn empty_value_is_rejected() {
        let result = parse_encryption_key("");
        assert_eq!(
            result.err(),
            Some(ConfigError::WrongLength { decoded_len: 0 })
        );
    }

    #[test]
    fn error_messages_do_not_contain_the_key_value() {
        let bad_inputs = [
            TEST_KEY_B64,
            "AAAA!!",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        ];
        for input in bad_inputs {
            if let Err(err) = parse_encryption_key(input) {
                let msg = err.to_string();
                assert!(!msg.contains(input), "error text leaked input: {msg}");
                assert!(msg.contains(ENCRYPTION_KEY_VAR));
            }
        }
        assert!(!ConfigError::Missing.to_string().contains(TEST_KEY_B64));
    }

    /// Builds a lookup over a fixed set of variables. Test values only.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, VarError> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            owned
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .ok_or(VarError::NotPresent)
        }
    }

    const PUBLIC: (&str, &str) = (PUBLIC_URL_VAR, "https://dockward.example.com");

    fn settings_err(pairs: &[(&str, &str)]) -> String {
        match load_settings_with(env_of(pairs)) {
            Err(err) => err.to_string(),
            Ok(_) => String::from("<no error>"),
        }
    }

    #[test]
    fn public_url_is_required() {
        let msg = settings_err(&[]);
        assert_eq!(msg, "DOCKWARD_PUBLIC_URL is required.");
    }

    #[test]
    fn public_url_accepts_https_origin() {
        let settings = load_settings_with(env_of(&[PUBLIC])).expect_test_ok();
        assert_eq!(settings.public_url, "https://dockward.example.com");
    }

    #[test]
    fn public_url_strips_trailing_slash() {
        let settings = load_settings_with(env_of(&[(PUBLIC_URL_VAR, "https://h.example.com/")]))
            .expect_test_ok();
        assert_eq!(settings.public_url, "https://h.example.com");
    }

    #[test]
    fn public_url_host_is_lowercased_and_default_port_dropped() {
        let cases = [
            (
                "https://Dockward.Example.COM:443/",
                "https://dockward.example.com",
            ),
            (
                "https://dockward.example.com:8443",
                "https://dockward.example.com:8443",
            ),
            // 80 is not the default for https, so it stays.
            ("https://h.example.com:80", "https://h.example.com:80"),
            ("http://LOCALHOST:80", "http://localhost"),
            ("http://localhost:8080/", "http://localhost:8080"),
        ];
        for (raw, expected) in cases {
            let settings = load_settings_with(env_of(&[(PUBLIC_URL_VAR, raw)])).expect_test_ok();
            assert_eq!(settings.public_url, expected, "{raw}");
        }
    }

    #[test]
    fn public_url_accepts_localhost_http_with_any_port() {
        for url in ["http://localhost", "http://localhost:8080", "HTTP://x"] {
            let result = load_settings_with(env_of(&[(PUBLIC_URL_VAR, url)]));
            assert_eq!(result.is_ok(), url.starts_with("http://localhost"), "{url}");
        }
    }

    #[test]
    fn public_url_rejects_plain_http_for_other_hosts_and_loopback_ips() {
        for url in [
            "http://dockward.example.com",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://localhost.example.com",
        ] {
            let msg = settings_err(&[(PUBLIC_URL_VAR, url)]);
            assert!(msg.starts_with("DOCKWARD_PUBLIC_URL is invalid"), "{msg}");
            assert!(!msg.contains(url), "error echoed the value: {msg}");
        }
    }

    #[test]
    fn public_url_rejects_other_schemes_and_bad_hosts() {
        for url in [
            "ftp://example.com",
            "example.org",
            "https://a b",
            "https://a..b",
            "https://h:0",
        ] {
            let msg = settings_err(&[(PUBLIC_URL_VAR, url)]);
            assert!(msg.starts_with("DOCKWARD_PUBLIC_URL is invalid"), "{msg}");
            assert!(!msg.contains(url), "error echoed the value: {msg}");
        }
    }

    #[test]
    fn boolean_flags_accept_true_and_false_in_any_case() {
        let settings = load_settings_with(env_of(&[
            PUBLIC,
            (ALLOW_PRIVATE_HARBOR_VAR, "TRUE"),
            (ALLOW_PRIVATE_OIDC_VAR, "false"),
            (ALLOW_PRIVATE_ALERTS_VAR, "True"),
        ]))
        .expect_test_ok();
        assert!(settings.allow_private_harbor);
        assert!(!settings.allow_private_oidc);
        assert!(settings.allow_private_alerts);
    }

    #[test]
    fn boolean_flags_default_to_false() {
        let settings = load_settings_with(env_of(&[PUBLIC])).expect_test_ok();
        assert!(!settings.allow_private_harbor);
        assert!(!settings.allow_private_oidc);
        assert!(!settings.allow_private_alerts);
    }

    #[test]
    fn each_boolean_flag_names_itself_when_invalid() {
        for var in [
            ALLOW_PRIVATE_HARBOR_VAR,
            ALLOW_PRIVATE_OIDC_VAR,
            ALLOW_PRIVATE_ALERTS_VAR,
        ] {
            for value in ["1", "yes", "0", ""] {
                let msg = settings_err(&[PUBLIC, (var, value)]);
                assert_eq!(msg, format!("{var} is invalid: must be true or false."));
            }
        }
    }

    #[test]
    fn data_dir_defaults_to_data_and_backup_dir_to_data_backups() {
        let settings = load_settings_with(env_of(&[PUBLIC])).expect_test_ok();
        assert_eq!(settings.data_dir, PathBuf::from("/data"));
        assert_eq!(settings.backup_dir, PathBuf::from("/data/backups"));
    }

    #[test]
    fn empty_path_variables_are_rejected_by_name() {
        let msg = settings_err(&[PUBLIC, (DATA_DIR_VAR, "  ")]);
        assert_eq!(msg, "DOCKWARD_DATA_DIR is invalid: must not be empty.");
        let msg = settings_err(&[PUBLIC, (BACKUP_DIR_VAR, "")]);
        assert_eq!(msg, "DOCKWARD_BACKUP_DIR is invalid: must not be empty.");
    }

    fn temp_base(tag: &str) -> PathBuf {
        let base =
            std::env::temp_dir().join(format!("dockward-backupdir-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        base
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0)
    }

    #[cfg(unix)]
    #[test]
    fn fresh_data_dir_gets_backups_with_mode_0700() {
        let base = temp_base("fresh");
        let data = base.join("data");
        prepare_data_dir(&data).expect_test_ok();
        prepare_backup_dir(&data.join("backups")).expect_test_ok();
        assert!(data.join("backups").is_dir());
        assert_eq!(mode_of(&data.join("backups")), 0o700);
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn custom_backup_dir_is_created_with_parents() {
        let base = temp_base("custom");
        let dir = base.join("elsewhere").join("bk");
        prepare_backup_dir(&dir).expect_test_ok();
        assert!(dir.is_dir());
        assert_eq!(mode_of(&dir), 0o700);
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn existing_backup_dir_keeps_its_mode_and_files() {
        use std::os::unix::fs::PermissionsExt;
        let base = temp_base("existing");
        fs::create_dir_all(&base).expect_test_ok();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).expect_test_ok();
        fs::write(base.join("keep.hgbk"), b"x").expect_test_ok();
        prepare_backup_dir(&base).expect_test_ok();
        assert_eq!(mode_of(&base), 0o755);
        assert!(base.join("keep.hgbk").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_backup_dir_is_not_chmodded() {
        use std::os::unix::fs::PermissionsExt;
        let base = temp_base("readonly");
        fs::create_dir_all(&base).expect_test_ok();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o500)).expect_test_ok();
        prepare_backup_dir(&base).expect_test_ok();
        assert_eq!(mode_of(&base), 0o500);
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect_test_ok();
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn backup_dir_that_cannot_be_created_fails_by_name() {
        let blocker = temp_base("blocker");
        fs::write(&blocker, b"test").expect_test_ok();
        let msg = prepare_backup_dir(&blocker.join("bk"))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            msg.starts_with("DOCKWARD_BACKUP_DIR is invalid: could not be created"),
            "{msg}"
        );
        let _ = fs::remove_file(&blocker);
    }

    #[test]
    fn load_settings_does_not_create_the_backup_dir() {
        let settings = load_settings_with(env_of(&[
            PUBLIC,
            (BACKUP_DIR_VAR, "/nonexistent-dockward-test/backups"),
        ]))
        .expect_test_ok();
        assert_eq!(
            settings.backup_dir,
            PathBuf::from("/nonexistent-dockward-test/backups")
        );
    }

    #[test]
    fn trusted_proxies_default_to_empty() {
        let settings = load_settings_with(env_of(&[PUBLIC])).expect_test_ok();
        assert!(settings.trusted_proxies.is_empty());
        let settings =
            load_settings_with(env_of(&[PUBLIC, (TRUSTED_PROXIES_VAR, "  ")])).expect_test_ok();
        assert!(settings.trusted_proxies.is_empty());
    }

    #[test]
    fn trusted_proxies_accept_ipv4_and_ipv6_cidrs() {
        let settings = load_settings_with(env_of(&[
            PUBLIC,
            (TRUSTED_PROXIES_VAR, "172.18.0.0/16, fd00:1::/48"),
        ]))
        .expect_test_ok();
        assert_eq!(settings.trusted_proxies.len(), 2);
        assert!(settings.trusted_proxies[0].contains("172.18.4.2".parse().expect_test_ok()));
        assert!(!settings.trusted_proxies[0].contains("172.19.0.1".parse().expect_test_ok()));
        assert!(settings.trusted_proxies[1].contains("fd00:1::9".parse().expect_test_ok()));
    }

    #[test]
    fn trusted_proxies_reject_host_bits_bare_ips_and_bad_entries() {
        for entry in [
            "10.0.0.1/8",
            "10.0.0.0",
            "10.0.0.0/33",
            "fd00::1/64",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "not-an-ip/8",
        ] {
            let msg = settings_err(&[PUBLIC, (TRUSTED_PROXIES_VAR, entry)]);
            assert!(
                msg.starts_with("DOCKWARD_TRUSTED_PROXIES is invalid: entry 1 "),
                "{msg}"
            );
        }
    }

    #[test]
    fn trusted_proxies_fail_on_any_invalid_entry_and_name_its_position() {
        let msg = settings_err(&[PUBLIC, (TRUSTED_PROXIES_VAR, "10.0.0.0/8,10.0.0.1/8")]);
        assert_eq!(
            msg,
            "DOCKWARD_TRUSTED_PROXIES is invalid: entry 2 has host bits set; use the network address."
        );
    }

    #[test]
    fn cidr_containment_respects_prefix_and_family() {
        let net = Cidr::parse("10.0.0.0/8").expect_test_ok();
        assert!(net.contains("10.255.1.1".parse().expect_test_ok()));
        assert!(!net.contains("11.0.0.1".parse().expect_test_ok()));
        assert!(!net.contains("::ffff:10.0.0.1".parse().expect_test_ok()));
        let all = Cidr::parse("0.0.0.0/0").expect_test_ok();
        assert!(all.contains("192.0.2.1".parse().expect_test_ok()));
        let host = Cidr::parse("203.0.113.7/32").expect_test_ok();
        assert!(host.contains("203.0.113.7".parse().expect_test_ok()));
        assert!(!host.contains("203.0.113.8".parse().expect_test_ok()));
    }

    #[test]
    fn data_dir_is_created_when_missing_and_is_writable() {
        let base = std::env::temp_dir().join(format!(
            "dockward-config-test-{}-create",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let nested = base.join("data");
        prepare_data_dir(&nested).expect_test_ok();
        assert!(nested.is_dir());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn data_dir_that_cannot_be_created_fails_by_name() {
        let blocker =
            std::env::temp_dir().join(format!("dockward-config-test-{}-file", std::process::id()));
        fs::write(&blocker, b"test").expect_test_ok();
        let err = prepare_data_dir(&blocker.join("data")).err();
        let msg = err.map(|e| e.to_string()).unwrap_or_default();
        assert!(
            msg.starts_with("DOCKWARD_DATA_DIR is invalid: could not be created"),
            "{msg}"
        );
        let _ = fs::remove_file(&blocker);
    }

    trait TestOk<T> {
        fn expect_test_ok(self) -> T;
    }

    impl<T, E: fmt::Debug> TestOk<T> for Result<T, E> {
        fn expect_test_ok(self) -> T {
            match self {
                Ok(value) => value,
                Err(err) => panic!("expected Ok in test, got {err:?}"),
            }
        }
    }

    #[test]
    fn legacy_name_is_a_fallback_and_the_new_name_wins() {
        let only_legacy = |name: &str| match name {
            "HARBORGATE_DATA_DIR" => Ok("/old".to_owned()),
            _ => Err(VarError::NotPresent),
        };
        assert_eq!(
            lookup_with_fallback(&only_legacy, DATA_DIR_VAR)
                .ok()
                .as_deref(),
            Some("/old")
        );
        let both = |name: &str| match name {
            "HARBORGATE_DATA_DIR" => Ok("/old".to_owned()),
            "DOCKWARD_DATA_DIR" => Ok("/new".to_owned()),
            _ => Err(VarError::NotPresent),
        };
        assert_eq!(
            lookup_with_fallback(&both, DATA_DIR_VAR).ok().as_deref(),
            Some("/new")
        );
        let neither = |_: &str| Err(VarError::NotPresent);
        assert!(matches!(
            lookup_with_fallback(&neither, DATA_DIR_VAR),
            Err(VarError::NotPresent)
        ));
    }

    #[test]
    fn old_key_is_read_from_its_own_variable() {
        let lookup = |name: &str| {
            if name == OLD_ENCRYPTION_KEY_VAR {
                Ok(TEST_KEY_B64.to_owned())
            } else {
                Err(VarError::NotPresent)
            }
        };
        let key = load_old_encryption_key_with(lookup);
        assert!(matches!(&key, Ok(k) if k.as_bytes() == &[0u8; 32]));
    }

    #[test]
    fn old_key_errors_name_the_old_variable_and_hide_the_value() {
        let missing = load_old_encryption_key_with(|_| Err(VarError::NotPresent)).err();
        let bad_base64 = load_old_encryption_key_with(|_| Ok("AAAA!!".to_owned())).err();
        let short = load_old_encryption_key_with(|_| Ok("AAAA".to_owned())).err();
        for err in [missing, bad_base64, short] {
            let text = err.map(|e| e.to_string()).unwrap_or_default();
            assert!(
                text.contains(OLD_ENCRYPTION_KEY_VAR),
                "the error does not name the old variable"
            );
        }
        let rendered = load_old_encryption_key_with(|_| Ok("AAAA!!".to_owned()))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(!rendered.contains("AAAA!!"), "the error echoes the value");
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = parse_encryption_key(TEST_KEY_B64);
        let rendered = match key {
            Ok(k) => format!("{k:?}"),
            Err(_) => String::new(),
        };
        assert_eq!(rendered, "EncryptionKey(<redacted>)");
    }
}
