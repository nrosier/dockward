//! Redaction of one scanner log line before anything is stored (#308).
//!
//! A scanner's stderr and the update steps' stdout can echo a registry URL with a password, an
//! `Authorization` header, or a token in a `key=value` pair. [`redact_line`] masks those values
//! with [`REDACTED`]. It runs on every stored line, before the line leaves the process, so a
//! secret never reaches the database, the log view or a trace.
//!
//! Patterns, applied in this order:
//! 1. `Authorization:` header values (the rest of the line is masked).
//! 2. URL userinfo (`scheme://user:pass@host`): the userinfo is masked, the host kept.
//! 3. Token prefixes `ghp_`, `gho_`, `ghs_`, `ghu_`, `github_pat_`, and the V1 ciphertext prefix
//!    `v1:` and Argon2 hashes `$argon2`: the token is masked.
//! 4. `Bearer <value>` and `Basic <value>` credentials, wherever they appear in the line.
//! 5. Webhook URL tokens: every path segment after a `services`, `hooks`, `webhook` or
//!    `webhooks` segment of a URL (Slack, Discord and similar webhook URLs).
//! 6. `key=value`, `key: value` and `"key":"value"` where the key name is a secret name by
//!    [`audit::is_secret_key_name`](crate::services::audit::is_secret_key_name), or names a
//!    session (`session`, `sid`), which covers session cookie values.

use crate::services::audit::is_secret_key_name;

/// The mask that replaces a secret value. The same text the application log uses.
pub const REDACTED: &str = "[redacted]";

/// Prefixes of GitHub tokens. The token is the prefix and the characters that follow it.
const GITHUB_PREFIXES: &[&str] = &["ghp_", "gho_", "ghs_", "ghu_", "github_pat_"];

/// Returns `line` with every secret-looking value masked. Plain text is returned unchanged.
pub fn redact_line(line: &str) -> String {
    let line = mask_authorization(line);
    let line = mask_userinfo(&line);
    let line = mask_tokens(&line);
    let line = mask_scheme_credentials(&line);
    let line = mask_webhook_paths(&line);
    mask_key_values(&line)
}

/// Masks everything after an `Authorization:` label (case-insensitive), keeping the label.
fn mask_authorization(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    let Some(at) = lowered.find("authorization") else {
        return line.to_owned();
    };
    let after_label = at + "authorization".len();
    let Some(colon_offset) = line[after_label..].find(':') else {
        return line.to_owned();
    };
    let value_start = after_label + colon_offset + 1;
    format!(
        "{}: {REDACTED}",
        line[..value_start].trim_end_matches(':').trim_end()
    )
}

/// Masks the userinfo of every `scheme://userinfo@host` in the line.
fn mask_userinfo(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(scheme_end) = rest.find("://") {
        let authority_start = scheme_end + "://".len();
        out.push_str(&rest[..authority_start]);
        let tail = &rest[authority_start..];
        let authority_end = tail
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        match authority.rfind('@') {
            Some(at) => {
                out.push_str(REDACTED);
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
}

/// Masks each token that starts with a GitHub prefix, the V1 prefix or an Argon2 hash.
fn mask_tokens(line: &str) -> String {
    let mut out = line.to_owned();
    for prefix in GITHUB_PREFIXES {
        out = mask_prefixed(&out, prefix, is_token_char);
    }
    out = mask_prefixed(&out, crate::auth::crypto::V1_PREFIX, is_value_char);
    mask_prefixed(&out, "$argon2", is_value_char)
}

/// Masks the credential after a `Bearer` or `Basic` word (case-insensitive, whole word).
fn mask_scheme_credentials(line: &str) -> String {
    let words: Vec<&str> = line.split(' ').collect();
    let mut masked: Vec<String> = Vec::with_capacity(words.len());
    let mut after_scheme = false;
    for word in words {
        if after_scheme && !word.is_empty() {
            masked.push(REDACTED.to_owned());
            after_scheme = false;
            continue;
        }
        after_scheme = word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic");
        masked.push(word.to_owned());
    }
    masked.join(" ")
}

/// Masks the path segments that follow a webhook marker segment in each URL of the line.
fn mask_webhook_paths(line: &str) -> String {
    const MARKERS: &[&str] = &["services", "hooks", "webhook", "webhooks"];
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(scheme_end) = rest.find("://") {
        let url_start = scheme_end + "://".len();
        out.push_str(&rest[..url_start]);
        let tail = &rest[url_start..];
        let url_end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '?' | '#'))
            .unwrap_or(tail.len());
        let url = &tail[..url_end];
        let mut segments = url.split('/');
        out.push_str(segments.next().unwrap_or_default());
        let mut masking = false;
        for segment in segments {
            out.push('/');
            if masking && !segment.is_empty() {
                out.push_str(REDACTED);
            } else {
                out.push_str(segment);
            }
            if MARKERS.contains(&segment.to_ascii_lowercase().as_str()) {
                masking = true;
            }
        }
        rest = &tail[url_end..];
    }
    out.push_str(rest);
    out
}

/// Replaces each occurrence of `prefix` and the run of `continues` characters after it.
fn mask_prefixed(text: &str, prefix: &str, continues: fn(char) -> bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(prefix) {
        out.push_str(&rest[..at]);
        out.push_str(REDACTED);
        let tail = &rest[at + prefix.len()..];
        let consumed = tail.find(|c: char| !continues(c)).unwrap_or(tail.len());
        rest = &tail[consumed..];
    }
    out.push_str(rest);
    out
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_value_char(c: char) -> bool {
    !(c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '&' | '}' | ')'))
}

/// Masks the value of each `key=value`, `key: value` and `"key":"value"` pair whose key name is
/// a secret name. Only the value is replaced; the key, the separator and any quotes stay.
fn mask_key_values(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if (c == '=' || c == ':') && is_secret_key_before(&chars, i) {
            out.push(c);
            let mut j = i + 1;
            while j < chars.len() && chars[j] == ' ' {
                out.push(' ');
                j += 1;
            }
            let quoted = j < chars.len() && chars[j] == '"';
            if quoted {
                out.push('"');
                j += 1;
            }
            let value_end = (j..chars.len())
                .find(|&k| {
                    if quoted {
                        chars[k] == '"'
                    } else {
                        !is_value_char(chars[k])
                    }
                })
                .unwrap_or(chars.len());
            if value_end > j {
                out.push_str(REDACTED);
            }
            i = value_end;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// True when the key name right before the separator at `at` is a secret name. The key may be
/// wrapped in quotes (`"key":`).
fn is_secret_key_before(chars: &[char], at: usize) -> bool {
    let mut end = at;
    if end > 0 && chars[end - 1] == '"' {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_key_char(chars[start - 1]) {
        start -= 1;
    }
    if start == end {
        return false;
    }
    let key: String = chars[start..end].iter().collect();
    is_secret_key_name(&key) || is_session_key_name(&key)
}

/// True for a key that names a session: a session cookie value must not be stored.
fn is_session_key_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    lowered.contains("session") || lowered == "sid"
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

#[cfg(test)]
mod tests;
