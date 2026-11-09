//! Runs the built binary's `healthcheck` subcommand and checks that it never prints a
//! secret from the environment, whether or not a server answers on the bind port.

use std::process::Command;

#[test]
fn healthcheck_prints_no_secret() {
    // Low-entropy markers, not real keys: the healthcheck never reads either variable,
    // so any value proves the point, and the secret scan does not flag these.
    let current = "marker-current-aaaaaaaaaaaaaaaa";
    let previous = "marker-previous-bbbbbbbbbbbbbbbb";
    let output = Command::new(env!("CARGO_BIN_EXE_harborgate"))
        .arg("healthcheck")
        .env("HARBORGATE_ENCRYPTION_KEY", current)
        .env("HARBORGATE_OLD_ENCRYPTION_KEY", previous)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains(current), "printed the encryption key");
    assert!(!text.contains(previous), "printed the old encryption key");
    if output.status.success() {
        assert!(text.is_empty(), "printed output on success: {text}");
    } else {
        assert_eq!(output.status.code(), Some(1));
        assert!(
            text.starts_with("healthcheck failed:"),
            "unexpected output: {text}"
        );
    }
}
