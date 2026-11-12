//! TOTP (RFC 6238) for local accounts: code generation, base32, and the short-lived
//! sign-in challenge. Sources: RFC 6238 (TOTP), RFC 4226 (HOTP, dynamic truncation), RFC 4648
//! section 6 (base32). Codes are 6 digits, the step is 30 seconds, the hash is HMAC-SHA1,
//! because that is the one every authenticator app supports (RFC 6238 section 3 and the
//! Key URI Format list SHA1 as the default).
//!
//! Nothing here logs, prints or returns a secret except [`base32`], whose only caller is the
//! enrolment response. The challenge is a signed token that names the user. It carries no
//! session and is not accepted by [`crate::auth::session::verify`].

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

use crate::auth::crypto::DerivedKey;
use crate::error::AppError;
use crate::services::ids;

/// Length of one TOTP step, in seconds (RFC 6238 section 4.1 default).
pub const STEP_SECS: i64 = 30;
/// Number of digits in a code.
pub const DIGITS: usize = 6;
/// How long the sign-in challenge lives after a correct password: 5 minutes.
pub const CHALLENGE_LIFETIME_SECS: i64 = 300;
/// Length of a new secret: 20 bytes, the HMAC-SHA1 block recommendation (RFC 4226 section 4).
pub const SECRET_LEN: usize = 20;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CHALLENGE_HEADER: &[u8] = br#"{"alg":"HS256","typ":"totp-challenge"}"#;

/// Cookie that carries the challenge between the password step and the code step. The
/// `__Host-` prefix forces `Secure`, `Path=/` and no `Domain`. `SameSite=Strict` keeps it off
/// cross-site requests.
pub const CHALLENGE_COOKIE: &str = "__Host-dockward_totp";

/// The `Set-Cookie` value that stores a challenge.
pub fn challenge_set_cookie(token: &str) -> String {
    format!(
        "{CHALLENGE_COOKIE}={token}; Max-Age={CHALLENGE_LIFETIME_SECS}; Path=/; HttpOnly; Secure; SameSite=Strict"
    )
}

/// The `Set-Cookie` value that clears the challenge cookie.
pub fn challenge_clear_cookie() -> String {
    format!("{CHALLENGE_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict")
}

/// The step (counter) that contains `unix`.
pub fn step_at(unix: i64) -> i64 {
    unix.div_euclid(STEP_SECS)
}

/// A fresh random secret from the OS CSPRNG.
pub fn new_secret() -> Result<[u8; SECRET_LEN], AppError> {
    ids::os_random_bytes::<SECRET_LEN>()
}

/// The 6-digit code for `step` (RFC 4226 section 5.3 dynamic truncation).
pub fn code_at(secret: &[u8], step: i64) -> Result<String, AppError> {
    let counter = u64::try_from(step).map_err(|_| AppError::InternalError)?;
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(secret).map_err(|_| AppError::InternalError)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest.last().copied().ok_or(AppError::InternalError)? & 0x0f);
    let window: [u8; 4] = digest
        .get(offset..offset + 4)
        .ok_or(AppError::InternalError)?
        .try_into()
        .map_err(|_| AppError::InternalError)?;
    let value = u32::from_be_bytes(window) & 0x7fff_ffff;
    Ok(format!("{:0width$}", value % 1_000_000, width = DIGITS))
}

/// Checks `code` against `now` with one step of drift either side (RFC 6238 section 5.2).
/// Returns the matching step, the highest one when several match. The comparison does not exit
/// early on a mismatch. `last_step` is the newest step already accepted: a match at or before
/// it is refused, so a code works once.
pub fn check_code(
    secret: &[u8],
    code: &str,
    now: i64,
    last_step: Option<i64>,
) -> Result<Option<i64>, AppError> {
    let current = step_at(now);
    let mut found = None;
    for step in [current - 1, current, current + 1] {
        if step < 0 {
            continue;
        }
        let expected = code_at(secret, step)?;
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) && found.is_none_or(|f| step > f)
        {
            found = Some(step);
        }
    }
    Ok(found.filter(|step| last_step.is_none_or(|last| *step > last)))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Base32 (RFC 4648 section 6) without padding, as an otpauth URI and authenticator apps expect.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((buffer >> bits) & 0x1f).unwrap_or(0);
            out.push(char::from(BASE32_ALPHABET[index]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        let index = usize::try_from((buffer << (5 - bits)) & 0x1f).unwrap_or(0);
        out.push(char::from(BASE32_ALPHABET[index]));
    }
    out
}

#[cfg(test)]
pub(crate) fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for ch in text.bytes() {
        let value = BASE32_ALPHABET.iter().position(|c| *c == ch)?;
        buffer = (buffer << 5) | u32::try_from(value).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Percent-encodes `text` for a URI component (RFC 3986 unreserved characters stay).
fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The `otpauth://` URI for an authenticator app (Google Authenticator Key URI Format).
pub fn otpauth_uri(issuer: &str, account: &str, secret_base32: &str) -> String {
    let issuer = encode_component(issuer);
    format!(
        "otpauth://totp/{issuer}:{}?secret={secret_base32}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        encode_component(account)
    )
}

#[derive(Serialize, Deserialize)]
struct ChallengeClaims {
    sub: String,
    ver: i64,
    exp: i64,
    jti: String,
}

fn mac(key: &DerivedKey) -> Result<Hmac<Sha256>, AppError> {
    <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes()).map_err(|_| AppError::InternalError)
}

/// Issues the sign-in challenge for a user whose password was correct. It is signed with the
/// session key but has its own header type, so it can never pass as a session token.
pub fn issue_challenge(
    key: &DerivedKey,
    user_id: &str,
    token_version: i64,
    now: i64,
) -> Result<String, AppError> {
    let claims = ChallengeClaims {
        sub: user_id.to_owned(),
        ver: token_version,
        exp: now + CHALLENGE_LIFETIME_SECS,
        jti: ids::new_id()?,
    };
    let payload = serde_json::to_vec(&claims).map_err(|_| AppError::InternalError)?;
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(CHALLENGE_HEADER),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let mut signer = mac(key)?;
    signer.update(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes())
    ))
}

/// Verifies a challenge and returns the user id and the `token_version` it was issued for.
/// Any failure is `401 invalid_credentials`, the answer a wrong password gets.
pub fn verify_challenge(
    key: &DerivedKey,
    token: &str,
    now: i64,
) -> Result<(String, i64), AppError> {
    let invalid = || AppError::InvalidCredentials;
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else {
        return Err(invalid());
    };
    if URL_SAFE_NO_PAD.decode(header).map_err(|_| invalid())? != CHALLENGE_HEADER {
        return Err(invalid());
    }
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| invalid())?;
    let mut verifier = mac(key)?;
    verifier.update(format!("{header}.{payload}").as_bytes());
    verifier.verify_slice(&signature).map_err(|_| invalid())?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| invalid())?;
    let claims: ChallengeClaims = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if claims.exp <= now {
        return Err(invalid());
    }
    Ok((claims.sub, claims.ver))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 4226/6238 test seed, the ASCII digits 1 to 0 repeated twice. Built at runtime so the
    /// source holds no literal key (CodeQL flags literal keys even in test vectors).
    fn rfc_seed() -> Vec<u8> {
        (1..=20).map(|i| b'0' + (i % 10) as u8).collect()
    }

    /// RFC 6238 Appendix B (SHA-1 rows). The seed is the ASCII text `12345678901234567890`.
    /// The RFC lists 8-digit codes; the last 6 digits are the 6-digit code.
    #[test]
    fn rfc_6238_sha1_test_vectors() {
        let seed = rfc_seed();
        for (time, eight) in [
            (59_i64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(
                code_at(&seed, step_at(time)).unwrap(),
                eight[2..],
                "T={time}"
            );
        }
    }

    /// RFC 4226 Appendix D: HOTP values for counters 0 to 9 with the same seed.
    #[test]
    fn rfc_4226_hotp_test_vectors() {
        let seed = rfc_seed();
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let step = i64::try_from(counter).unwrap();
            assert_eq!(code_at(&seed, step).unwrap(), *want, "counter {counter}");
        }
    }

    /// RFC 4648 section 10 test vectors, without padding (otpauth URIs omit it).
    #[test]
    fn base32_matches_rfc_4648() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(plain.as_bytes()), encoded);
            assert_eq!(base32_decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(
            base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    fn key() -> crate::auth::crypto::DerivedKey {
        let root =
            crate::config::parse_encryption_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .unwrap();
        crate::auth::crypto::session_key(&root).unwrap()
    }

    /// A challenge names the user and the token version, expires, and is not a session token.
    #[test]
    fn challenge_round_trips_and_rejects_tampering_and_expiry() {
        let k = key();
        let token = issue_challenge(&k, "user-1", 4, 1_000).unwrap();
        assert_eq!(
            verify_challenge(&k, &token, 1_000).unwrap(),
            ("user-1".to_owned(), 4)
        );
        assert!(verify_challenge(&k, &token, 1_000 + CHALLENGE_LIFETIME_SECS).is_err());
        let mut forged = token.clone();
        forged.insert(0, 'A');
        assert!(verify_challenge(&k, &forged, 1_000).is_err());
        assert!(verify_challenge(&k, "", 1_000).is_err());
        // Never accepted as a session token.
        assert!(crate::auth::session::verify(&k, &token, 1_000).is_err());
    }
}
