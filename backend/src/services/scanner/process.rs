//! The out-of-process scanner runner (`specs/spinoff-local-scan.md`, section 7; decisions 5, 19,
//! 28 and 29).
//!
//! Rules enforced here, for every scanner run:
//! - The program is an absolute path and the arguments are an argument vector. No shell runs,
//!   and no `PATH` is searched.
//! - The environment is cleared first. Only the variables a caller passes in the allow-list are
//!   set, so `DOCKWARD_ENCRYPTION_KEY` and the other secrets never reach the child.
//! - The child leads its own process group. On timeout, or when its captured output goes over
//!   the cap, the whole group is killed.
//! - stdout is captured up to the cap. stderr is drained and discarded: it is never stored, and
//!   never logged.
//! - One scanner process runs at a time, through a lock held by [`ScannerRunner`].
//!
//! This module holds no database code.

use std::ffi::OsString;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::error::{AppError, ScannerFault};

/// The default timeout of one scanner run (decision 19).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// The default cap on captured output: 64 MiB (decision 19).
pub const DEFAULT_OUTPUT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Read chunk size for captured output.
const CHUNK_BYTES: usize = 64 * 1024;

/// The limits of one run. Operator settings replace the defaults (section 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub timeout: Duration,
    pub output_max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            output_max_bytes: DEFAULT_OUTPUT_MAX_BYTES,
        }
    }
}

/// One run request. `program` must be absolute. `env` is the allow-list: the only variables the
/// child sees.
#[derive(Debug)]
pub struct Invocation<'a> {
    pub program: &'a Path,
    pub args: &'a [OsString],
    pub env: &'a [(OsString, OsString)],
    pub limits: Limits,
}

/// Runs scanner processes one at a time. Clone the handle to share the lock.
#[derive(Debug, Clone, Default)]
pub struct ScannerRunner {
    lock: Arc<Mutex<()>>,
}

impl ScannerRunner {
    /// Creates a runner with its own lock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs one invocation and returns its captured stdout. Failures return
    /// [`AppError::Scanner`] with one of the fixed texts of section 6.
    pub async fn run(&self, invocation: Invocation<'_>) -> Result<Vec<u8>, AppError> {
        let _guard = self.lock.lock().await;
        run_unlocked(&invocation).await.map_err(AppError::Scanner)
    }
}

/// Runs one invocation with no lock. The caller holds the runner lock.
async fn run_unlocked(invocation: &Invocation<'_>) -> Result<Vec<u8>, ScannerFault> {
    if !invocation.program.is_absolute() {
        return Err(ScannerFault::Failed);
    }
    let mut command = Command::new(invocation.program);
    command
        .args(invocation.args)
        .env_clear()
        .envs(invocation.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command.spawn().map_err(|_| ScannerFault::Failed)?;
    let pid = child.id();
    let (Some(mut stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        kill_group(pid);
        return Err(ScannerFault::Failed);
    };
    // stderr is drained on its own task so a chatty child cannot block on a full pipe. It is
    // discarded, never stored or logged.
    let stderr_drain = tokio::spawn(async move {
        let mut stderr = stderr;
        drain(&mut stderr).await;
    });
    let cap = invocation.limits.output_max_bytes;
    // A background child of the leader inherits stdout, so stdout may not reach its end once the
    // leader has exited. The read therefore ends at whichever comes first: stdout's end, or the
    // leader's exit. The leader is waited for, and then its group is killed while the leader is
    // still unreaped, so the pid is still ours. Bytes read before the exit are kept.
    let work = async {
        let (bytes, status) = read_until_exit(&mut stdout, cap, &mut child).await?;
        kill_group(pid);
        Ok::<_, ScannerFault>((bytes, status))
    };
    let outcome = tokio::time::timeout(invocation.limits.timeout, work).await;
    // The group is killed only while the child is unreaped (timeout, or a read fault before the
    // wait). After a successful wait the pid can be reused, so it is never signalled then.
    let result = match outcome {
        Err(_elapsed) => {
            kill_group(pid);
            Err(ScannerFault::TimedOut)
        }
        Ok(Err(fault)) => {
            kill_group(pid);
            Err(fault)
        }
        Ok(Ok((bytes, status))) => finish(bytes, status),
    };
    stderr_drain.abort();
    result
}

/// Maps a finished child to its output or to `scanner failed`.
fn finish(bytes: Vec<u8>, status: ExitStatus) -> Result<Vec<u8>, ScannerFault> {
    if status.success() {
        Ok(bytes)
    } else {
        Err(ScannerFault::Failed)
    }
}

/// Reads stdout until the leader exits, and returns the bytes with the exit status. The leader is
/// waited for, not the pipe: a child left in the group may hold stdout open after the leader is
/// done. After the exit, the bytes already in the pipe are drained without blocking, still under
/// the cap. Returns [`ScannerFault::OutputTooLarge`] as soon as the total would pass `cap`.
async fn read_until_exit(
    stdout: &mut tokio::process::ChildStdout,
    cap: u64,
    child: &mut tokio::process::Child,
) -> Result<(Vec<u8>, ExitStatus), ScannerFault> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; CHUNK_BYTES];
    let status = loop {
        tokio::select! {
            status = child.wait() => {
                break status.map_err(|_| ScannerFault::Failed)?;
            }
            read = stdout.read(&mut chunk) => {
                let read = read.map_err(|_| ScannerFault::Failed)?;
                if read == 0 {
                    // stdout closed before the leader exited. Keep waiting for the leader.
                    break child.wait().await.map_err(|_| ScannerFault::Failed)?;
                }
                push_capped(&mut out, &chunk[..read], cap)?;
            }
        }
    };
    // The leader is gone. Drain what is already buffered, without waiting on a pipe a child may
    // still hold open.
    loop {
        match tokio::time::timeout(Duration::from_millis(50), stdout.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => push_capped(&mut out, &chunk[..read], cap)?,
        }
    }
    Ok((out, status))
}

/// Appends bytes unless the total would pass `cap`.
fn push_capped(out: &mut Vec<u8>, bytes: &[u8], cap: u64) -> Result<(), ScannerFault> {
    let total = out.len().saturating_add(bytes.len());
    match u64::try_from(total) {
        Ok(total) if total <= cap => {
            out.extend_from_slice(bytes);
            Ok(())
        }
        _ => Err(ScannerFault::OutputTooLarge),
    }
}

/// Drains a stream and discards it. Errors are ignored, because stderr is never kept or logged.
async fn drain<R>(reader: &mut R)
where
    R: AsyncRead + Unpin,
{
    let mut sink = tokio::io::sink();
    let _ = tokio::io::copy(reader, &mut sink).await;
}

/// Kills every process in the child's group. The group id is the child's pid, because the child
/// was started with `process_group(0)`. A failure (the group is already gone) is ignored.
fn kill_group(pid: Option<u32>) {
    let Some(pid) = pid else {
        return;
    };
    let Ok(raw) = i32::try_from(pid) else {
        return;
    };
    let _ = killpg(Pid::from_raw(raw), Signal::SIGKILL);
}

#[cfg(test)]
pub(crate) mod tests;
