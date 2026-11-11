use super::*;

#[test]
fn url_userinfo_is_masked_and_the_host_is_kept() {
    let line = "pulling https://robot:s3cret@registry.example.com/v2/app";
    let out = redact_line(line);
    assert!(!out.contains("s3cret"), "{out}");
    assert!(!out.contains("robot"), "{out}");
    assert!(out.contains("registry.example.com/v2/app"), "{out}");
}

#[test]
fn authorization_header_value_is_masked() {
    let out = redact_line("GET /v2 Authorization: Basic dXNlcjpwYXNz");
    assert!(!out.contains("dXNlcjpwYXNz"), "{out}");
    assert!(out.contains("Authorization: [redacted]"), "{out}");
}

#[test]
fn key_equals_value_is_masked_for_a_secret_name() {
    let out = redact_line("config loaded token=abc123 region=eu");
    assert!(!out.contains("abc123"), "{out}");
    assert!(out.contains("token=[redacted]"), "{out}");
    assert!(out.contains("region=eu"), "{out}");
}

#[test]
fn key_colon_value_is_masked_for_a_secret_name() {
    let out = redact_line("password: hunter2");
    assert!(!out.contains("hunter2"), "{out}");
    assert!(out.contains("password: [redacted]"), "{out}");
}

#[test]
fn json_quoted_key_value_is_masked_for_a_secret_name() {
    let out = redact_line(r#"{"client_secret":"zzz-value","name":"ok"}"#);
    assert!(!out.contains("zzz-value"), "{out}");
    assert!(out.contains(r#""client_secret":"[redacted]""#), "{out}");
    assert!(out.contains(r#""name":"ok""#), "{out}");
}

#[test]
fn github_token_prefixes_are_masked() {
    for token in [
        "ghp_abcDEF123",
        "gho_abcDEF123",
        "ghs_abcDEF123",
        "ghu_abcDEF123",
        "github_pat_11ABC_xyz",
    ] {
        let out = redact_line(&format!("auth ok with {token} done"));
        assert!(!out.contains(token), "{token} leaked: {out}");
        assert!(out.contains("with [redacted] done"), "{out}");
    }
}

#[test]
fn v1_ciphertext_and_argon2_hash_are_masked() {
    let out = redact_line("stored v1:AAAA.BBBB and hash $argon2id$v=19$m=1 end");
    assert!(!out.contains("AAAA.BBBB"), "{out}");
    assert!(!out.contains("$argon2id"), "{out}");
    assert!(
        out.contains("stored [redacted] and hash [redacted] end"),
        "{out}"
    );
}

#[test]
fn plain_text_is_unchanged() {
    for line in [
        "trivy: vulnerability DB downloaded",
        "grype db update: 3 files",
        "scanner timed out at 600 seconds",
        "https://registry.example.com/v2/app",
        "",
    ] {
        assert_eq!(redact_line(line), line);
    }
}
