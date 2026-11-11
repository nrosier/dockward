use std::sync::Mutex;

use super::*;
use crate::error::ScannerFault;

/// A fake database tool. It reports one build time, or fails the update.
struct FakeTool {
    built_at: i64,
    fail_update: bool,
}

impl DatabaseTool for FakeTool {
    async fn update(&self, _scanner: Scanner) -> Result<(), AppError> {
        if self.fail_update {
            Err(AppError::Scanner(
                crate::error::ScannerFault::DatabaseNotAvailable,
            ))
        } else {
            Ok(())
        }
    }

    async fn built_at(&self, _scanner: Scanner) -> Result<i64, AppError> {
        Ok(self.built_at)
    }
}

/// A fake store. It records every commit and every `job_runs` row, so a test can see what was
/// queued and what was recorded.
struct FakeStore {
    stored: Option<i64>,
    digests: Vec<String>,
    commits: Mutex<Vec<(Scanner, i64, Vec<String>)>>,
    runs: Mutex<Vec<(RunTiming, Option<String>)>>,
}

impl FakeStore {
    fn new(stored: Option<i64>, digests: &[&str]) -> Self {
        Self {
            stored,
            digests: digests.iter().map(|d| (*d).to_owned()).collect(),
            commits: Mutex::new(Vec::new()),
            runs: Mutex::new(Vec::new()),
        }
    }

    fn commits(&self) -> Vec<(Scanner, i64, Vec<String>)> {
        match self.commits.lock() {
            Ok(guard) => guard.clone(),
            Err(poison) => poison.into_inner().clone(),
        }
    }

    fn runs(&self) -> Vec<(RunTiming, Option<String>)> {
        match self.runs.lock() {
            Ok(guard) => guard.clone(),
            Err(poison) => poison.into_inner().clone(),
        }
    }
}

impl RefreshStore for FakeStore {
    async fn record_run(
        &self,
        _scanner: Scanner,
        run: RunTiming,
        error: Option<&str>,
    ) -> Result<(), AppError> {
        let mut guard = match self.runs.lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        guard.push((run, error.map(str::to_owned)));
        Ok(())
    }

    async fn stored_built_at(&self, _scanner: Scanner) -> Result<Option<i64>, AppError> {
        Ok(self.stored)
    }

    async fn stored_platform_digests(&self) -> Result<Vec<String>, AppError> {
        Ok(self.digests.clone())
    }

    async fn commit_newer(
        &self,
        scanner: Scanner,
        built_at: i64,
        digests: &[String],
    ) -> Result<usize, AppError> {
        let mut guard = match self.commits.lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        guard.push((scanner, built_at, digests.to_vec()));
        Ok(digests.len())
    }
}

async fn run(tool: &FakeTool, store: &FakeStore) -> RefreshOutcome {
    match refresh(tool, store, Scanner::Trivy, || 0).await {
        Ok(outcome) => outcome,
        Err(err) => panic!("refresh failed: {err:?}"),
    }
}

#[tokio::test]
async fn an_unchanged_database_queues_nothing() {
    let tool = FakeTool {
        built_at: 1_000,
        fail_update: false,
    };
    let store = FakeStore::new(Some(1_000), &["sha256:aa", "sha256:bb"]);
    assert_eq!(run(&tool, &store).await, RefreshOutcome::Unchanged);
    assert!(
        store.commits().is_empty(),
        "no commit when nothing is newer"
    );
}

#[tokio::test]
async fn an_older_database_queues_nothing() {
    let tool = FakeTool {
        built_at: 900,
        fail_update: false,
    };
    let store = FakeStore::new(Some(1_000), &["sha256:aa"]);
    assert_eq!(run(&tool, &store).await, RefreshOutcome::Unchanged);
    assert!(store.commits().is_empty());
}

#[tokio::test]
async fn a_newer_database_queues_one_rescan_per_stored_digest() {
    let tool = FakeTool {
        built_at: 2_000,
        fail_update: false,
    };
    // A duplicate digest is queued once.
    let store = FakeStore::new(Some(1_000), &["sha256:bb", "sha256:aa", "sha256:bb"]);
    let outcome = run(&tool, &store).await;
    assert_eq!(
        outcome,
        RefreshOutcome::Updated {
            built_at: 2_000,
            rescans: 2,
        }
    );
    let commits = store.commits();
    assert_eq!(commits.len(), 1);
    let (scanner, built_at, digests) = &commits[0];
    assert_eq!(*scanner, Scanner::Trivy);
    assert_eq!(*built_at, 2_000);
    assert_eq!(
        digests,
        &vec!["sha256:aa".to_owned(), "sha256:bb".to_owned()]
    );
}

#[tokio::test]
async fn the_first_database_is_stored_and_rescans_stored_images() {
    let tool = FakeTool {
        built_at: 500,
        fail_update: false,
    };
    let store = FakeStore::new(None, &["sha256:cc"]);
    assert_eq!(
        run(&tool, &store).await,
        RefreshOutcome::Updated {
            built_at: 500,
            rescans: 1,
        }
    );
}

#[tokio::test]
async fn a_newer_database_with_no_stored_images_queues_nothing_but_stores_the_time() {
    let tool = FakeTool {
        built_at: 2_000,
        fail_update: false,
    };
    let store = FakeStore::new(Some(1_000), &[]);
    assert_eq!(
        run(&tool, &store).await,
        RefreshOutcome::Updated {
            built_at: 2_000,
            rescans: 0,
        }
    );
    assert_eq!(store.commits().len(), 1);
}

#[tokio::test]
async fn a_failed_update_leaves_the_old_database_and_queues_nothing() {
    let tool = FakeTool {
        built_at: 2_000,
        fail_update: true,
    };
    let store = FakeStore::new(Some(1_000), &["sha256:aa"]);
    let result = refresh(&tool, &store, Scanner::Grype, || 0).await;
    assert!(result.is_err(), "the failure is returned");
    assert!(store.commits().is_empty(), "nothing is stored on failure");
    assert_eq!(
        store
            .runs()
            .iter()
            .map(|run| run.1.clone())
            .collect::<Vec<_>>(),
        vec![Some("scanner database not available".to_owned())],
        "the failed run is recorded with its fixed text"
    );
}

#[tokio::test]
async fn every_refresh_records_one_job_run() {
    let unchanged = FakeStore::new(Some(1_000), &["sha256:aa"]);
    let tool = FakeTool {
        built_at: 1_000,
        fail_update: false,
    };
    let _ = run(&tool, &unchanged).await;
    assert_eq!(
        unchanged
            .runs()
            .iter()
            .map(|run| run.1.clone())
            .collect::<Vec<_>>(),
        vec![None],
        "a successful run is recorded"
    );

    let newer = FakeStore::new(Some(1_000), &["sha256:aa"]);
    let tool = FakeTool {
        built_at: 2_000,
        fail_update: false,
    };
    let _ = run(&tool, &newer).await;
    assert_eq!(
        newer
            .runs()
            .iter()
            .map(|run| run.1.clone())
            .collect::<Vec<_>>(),
        vec![None]
    );
}

#[tokio::test]
async fn a_run_records_the_real_start_and_finish_from_the_clock() {
    use std::sync::atomic::{AtomicI64, Ordering};
    // Each clock read advances by 5 seconds: the first read is the start, the second the finish.
    let now = AtomicI64::new(1_000);
    let clock = || now.fetch_add(5, Ordering::Relaxed);
    let store = FakeStore::new(Some(1_000), &["sha256:aa"]);
    let tool = FakeTool {
        built_at: 1_000,
        fail_update: false,
    };

    assert!(matches!(
        refresh(&tool, &store, Scanner::Trivy, clock).await,
        Ok(RefreshOutcome::Unchanged)
    ));

    let runs = store.runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].0,
        RunTiming {
            started_at: 1_000,
            finished_at: 1_005
        }
    );
    assert!(runs[0].0.finished_at > runs[0].0.started_at);
}

#[tokio::test]
async fn a_scanner_fault_keeps_its_own_text_on_the_run() {
    let store = FakeStore::new(None, &[]);
    let tool = FakeTool {
        built_at: 1_000,
        fail_update: true,
    };

    assert!(refresh(&tool, &store, Scanner::Trivy, || 0).await.is_err());

    let runs = store.runs();
    assert_eq!(runs[0].1.as_deref(), Some("scanner database not available"));
}

#[test]
fn a_non_scanner_error_is_one_fixed_text() {
    assert_eq!(run_error_text(&AppError::InternalError), "scanner failed");
    assert_eq!(
        run_error_text(&AppError::Scanner(ScannerFault::TimedOut)),
        "scanner timed out"
    );
}
