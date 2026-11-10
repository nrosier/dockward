use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nix::sys::signal::kill;
use nix::unistd::Pid;

use super::*;
use crate::error::{AppError, ScannerFault};

/// Serialises the tests that change this process's environment. In edition 2024 `set_var` is
/// unsafe, because another thread may read the environment at the same time.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh, empty directory under the system temp dir, for one test's scripts.
fn scratch_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "harborgate-scanner-{name}-{}-{seq}-{nanos}",
        std::process::id()
    ));
    if let Err(err) = std::fs::create_dir_all(&dir) {
        panic!("scratch dir could not be created: {err}");
    }
    dir
}

/// Writes an executable `/bin/sh` script into `dir` and returns its absolute path.
fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    if let Err(err) = std::fs::write(&path, format!("#!/bin/sh\n{body}\n")) {
        panic!("script could not be written: {err}");
    }
    if let Err(err) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)) {
        panic!("script could not be made executable: {err}");
    }
    path
}

fn runtime() -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => panic!("test runtime failed to start: {err}"),
    }
}

fn limits(timeout_ms: u64, output_max_bytes: u64) -> Limits {
    Limits {
        timeout: Duration::from_millis(timeout_ms),
        output_max_bytes,
    }
}

fn fault_of(result: Result<Vec<u8>, AppError>) -> ScannerFault {
    match result {
        Err(AppError::Scanner(fault)) => fault,
        Err(other) => panic!("expected a scanner fault, got {other:?}"),
        Ok(bytes) => panic!("expected a failure, got {} bytes", bytes.len()),
    }
}

#[test]
fn a_successful_run_returns_its_stdout() {
    let dir = scratch_dir("ok");
    let script = write_script(&dir, "ok.sh", "printf 'report-body'");
    let args: Vec<OsString> = Vec::new();
    let env: Vec<(OsString, OsString)> = Vec::new();
    let result = runtime().block_on(ScannerRunner::new().run(Invocation {
        program: &script,
        args: &args,
        env: &env,
        limits: limits(10_000, 1_024),
    }));
    let _ = std::fs::remove_dir_all(&dir);
    match result {
        Ok(bytes) => assert_eq!(bytes, b"report-body"),
        Err(err) => panic!("expected output, got {err:?}"),
    }
}

#[test]
fn a_non_zero_exit_is_scanner_failed_and_stderr_is_not_returned() {
    let dir = scratch_dir("exit");
    let script = write_script(
        &dir,
        "fail.sh",
        "printf 'secret-stderr-text' 1>&2\nprintf 'partial'\nexit 1",
    );
    let args: Vec<OsString> = Vec::new();
    let env: Vec<(OsString, OsString)> = Vec::new();
    let result = runtime().block_on(ScannerRunner::new().run(Invocation {
        program: &script,
        args: &args,
        env: &env,
        limits: limits(10_000, 1_024),
    }));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(fault_of(result), ScannerFault::Failed);
}

#[test]
fn a_relative_program_path_is_refused_before_any_spawn() {
    let args: Vec<OsString> = Vec::new();
    let env: Vec<(OsString, OsString)> = Vec::new();
    let result = runtime().block_on(ScannerRunner::new().run(Invocation {
        program: Path::new("trivy"),
        args: &args,
        env: &env,
        limits: limits(10_000, 1_024),
    }));
    assert_eq!(fault_of(result), ScannerFault::Failed);
}

#[test]
fn the_child_sees_only_the_allow_list_and_not_a_parent_variable() {
    let _guard = match ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poison) => poison.into_inner(),
    };
    // A canary set in the parent. The child must not see it, because the environment is cleared.
    let canary = "HARBORGATE_SCANNER_TEST_CANARY";
    // SAFETY: ENV_LOCK serialises environment access in this test binary, and the variable is
    // removed below before any assertion can panic.
    unsafe { std::env::set_var(canary, "canary-value") };

    let dir = scratch_dir("env");
    // `export -p` lists the variables the shell exports, which is the child's environment.
    let script = write_script(&dir, "env.sh", "export -p");
    let args: Vec<OsString> = Vec::new();
    let env: Vec<(OsString, OsString)> = vec![(
        OsString::from("DOCKWARD_ALLOWED_TEST"),
        OsString::from("allowed-value"),
    )];
    let result = runtime().block_on(ScannerRunner::new().run(Invocation {
        program: &script,
        args: &args,
        env: &env,
        limits: limits(10_000, 64 * 1024),
    }));
    // SAFETY: as above; the lock is still held.
    unsafe { std::env::remove_var(canary) };
    let _ = std::fs::remove_dir_all(&dir);

    let listing = match result {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(err) => panic!("env run failed: {err:?}"),
    };
    assert!(
        !listing.contains(canary),
        "the parent canary must not reach the child"
    );
    assert!(
        !listing.contains("canary-value"),
        "the parent canary value must not reach the child"
    );
    assert!(
        listing.contains("DOCKWARD_ALLOWED_TEST"),
        "an allow-listed variable must reach the child"
    );
    assert!(
        !listing.contains("PATH="),
        "PATH is not passed to the child"
    );
}

#[test]
fn a_timeout_kills_the_whole_process_group() {
    let dir = scratch_dir("timeout");
    let pidfile = dir.join("grandchild.pid");
    // The shell starts a long-running grandchild and records its pid, then waits. Only a group
    // kill stops the grandchild too.
    let script = write_script(
        &dir,
        "hang.sh",
        "/bin/sleep 60 &\necho $! > \"$1\"\n/bin/sleep 60",
    );
    let args: Vec<OsString> = vec![pidfile.as_os_str().to_owned()];
    let env: Vec<(OsString, OsString)> = Vec::new();
    let started = Instant::now();
    let result = runtime().block_on(ScannerRunner::new().run(Invocation {
        program: &script,
        args: &args,
        env: &env,
        limits: limits(400, 1_024),
    }));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the timeout must not wait for the sleep"
    );
    assert_eq!(fault_of(result), ScannerFault::TimedOut);

    let grandchild = read_pid(&pidfile);
    let gone = wait_until_gone(grandchild, Duration::from_secs(5));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(gone, "the grandchild must be killed with its group");
}

#[test]
fn a_background_child_left_by_a_successful_run_is_killed() {
    let dir = scratch_dir("orphan");
    let pidfile = dir.join("orphan.pid");
    // The leader prints its report, starts a background sleep, records its pid, and exits 0.
    let script = write_script(
        &dir,
        "orphan.sh",
        "/bin/sleep 60 &\necho $! > \"$1\"\nprintf 'report'",
    );
    let args: Vec<OsString> = vec![pidfile.as_os_str().to_owned()];
    let env: Vec<(OsString, OsString)> = Vec::new();
    let result = runtime().block_on(ScannerRunner::new().run(Invocation {
        program: &script,
        args: &args,
        env: &env,
        limits: limits(10_000, 1_024),
    }));
    let orphan = read_pid(&pidfile);
    let gone = wait_until_gone(orphan, Duration::from_secs(5));
    let state = std::process::Command::new("/bin/ps")
        .args(["-o", "pid=,ppid=,stat=,command=", "-p", &orphan.to_string()])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    match result {
        Ok(bytes) => assert_eq!(bytes, b"report"),
        Err(err) => panic!("expected the report, got {err:?}"),
    }
    assert!(
        gone,
        "the background child must not outlive the run; state: {state:?}"
    );
}

#[test]
fn an_oversized_output_is_refused_with_the_fixed_failure() {
    let dir = scratch_dir("cap");
    // An endless stream. The cap must stop it, and the group must be killed.
    let script = write_script(&dir, "flood.sh", "while :; do printf 'xxxxxxxxxx'; done");
    let args: Vec<OsString> = Vec::new();
    let env: Vec<(OsString, OsString)> = Vec::new();
    let started = Instant::now();
    let result = runtime().block_on(ScannerRunner::new().run(Invocation {
        program: &script,
        args: &args,
        env: &env,
        limits: limits(30_000, 1_000),
    }));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the cap must end the run before the timeout"
    );
    assert_eq!(fault_of(result), ScannerFault::OutputTooLarge);
}

#[test]
fn output_exactly_at_the_cap_is_accepted() {
    let dir = scratch_dir("exact");
    let script = write_script(&dir, "exact.sh", "printf 'abcdefghij'");
    let args: Vec<OsString> = Vec::new();
    let env: Vec<(OsString, OsString)> = Vec::new();
    let result = runtime().block_on(ScannerRunner::new().run(Invocation {
        program: &script,
        args: &args,
        env: &env,
        limits: limits(10_000, 10),
    }));
    let _ = std::fs::remove_dir_all(&dir);
    match result {
        Ok(bytes) => assert_eq!(bytes.len(), 10),
        Err(err) => panic!("output at the cap must pass, got {err:?}"),
    }
}

fn read_pid(path: &Path) -> i32 {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => panic!("grandchild pid file missing: {err}"),
    };
    match text.trim().parse::<i32>() {
        Ok(pid) => pid,
        Err(err) => panic!("grandchild pid unreadable: {err}"),
    }
}

/// Polls until the process is gone or only a zombie is left. A killed child that its parent has
/// not reaped still answers `kill(pid, 0)`, but it no longer runs. Its state is read from `ps`.
fn wait_until_gone(pid: i32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if !is_running(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether `pid` exists and is not a zombie. `ps -o stat=` prints `Z` for a zombie. An empty
/// answer means the process is gone.
fn is_running(pid: i32) -> bool {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output();
    match output {
        Ok(out) => {
            let state = String::from_utf8_lossy(&out.stdout);
            let state = state.trim();
            !state.is_empty() && !state.starts_with('Z')
        }
        Err(_) => kill(Pid::from_raw(pid), None).is_ok(),
    }
}
