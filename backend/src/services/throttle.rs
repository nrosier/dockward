//! Failed-login throttling per (account, client IP). Source: `specs/security.md`
//! (Authentication, Failed-login throttling). There is no lockout. After 5
//! consecutive failures for a pair, each further attempt waits 2^(n-5) seconds after
//! the previous failure, capped at 60 seconds. A success resets the pair.
//!
//! The clock is injected (see [`LoginThrottle::with_clock`]), so tests can freeze it
//! and stay deterministic under CPU load. The state is in memory and resets on
//! restart. That is a documented limit of v1.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Consecutive failures before any delay applies.
pub const FREE_FAILURES: u32 = 5;
/// Upper bound on the wait between attempts.
pub const MAX_WAIT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
struct PairState {
    failures: u32,
    last_failure: Instant,
}

/// Failure counter and delay, keyed by `(username, client IP)`.
/// The time source. The system clock in production, a fixed clock in tests.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

#[derive(Clone)]
pub struct LoginThrottle {
    pairs: Arc<Mutex<HashMap<(String, String), PairState>>>,
    clock: Clock,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

/// The wait that applies after `failures` consecutive failures. Zero below the
/// threshold. Otherwise 2^(failures - 5) seconds, capped at [`MAX_WAIT`].
pub fn wait_after(failures: u32) -> Duration {
    if failures < FREE_FAILURES {
        return Duration::ZERO;
    }
    let exponent = failures - FREE_FAILURES;
    // Cap the shift so large counts cannot overflow. The cap applies from 2^6 onward.
    let secs = if exponent >= 6 {
        MAX_WAIT.as_secs()
    } else {
        1_u64 << exponent
    };
    Duration::from_secs(secs).min(MAX_WAIT)
}

impl LoginThrottle {
    /// A throttle that reads the system clock.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(Instant::now))
    }

    /// A throttle that reads time from `clock`. Used by tests to freeze time.
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            pairs: Arc::default(),
            clock,
        }
    }

    /// The current time from this throttle's clock. Handlers take `now` from here so
    /// the throttle and its callers agree on one time source.
    pub fn now(&self) -> Instant {
        (self.clock)()
    }

    /// Returns `true` when an attempt for this pair must wait and be refused without a
    /// password check.
    pub fn is_blocked(&self, username: &str, ip: &str, now: Instant) -> bool {
        let Ok(map) = self.pairs.lock() else {
            // A poisoned lock fails closed: refuse rather than skip the throttle.
            return true;
        };
        match map.get(&(username.to_owned(), ip.to_owned())) {
            Some(state) => {
                let wait = wait_after(state.failures);
                now.duration_since(state.last_failure) < wait
            }
            None => false,
        }
    }

    /// Records a failed attempt for the pair at `now`.
    pub fn record_failure(&self, username: &str, ip: &str, now: Instant) {
        if let Ok(mut map) = self.pairs.lock() {
            let entry = map
                .entry((username.to_owned(), ip.to_owned()))
                .or_insert(PairState {
                    failures: 0,
                    last_failure: now,
                });
            entry.failures = entry.failures.saturating_add(1);
            entry.last_failure = now;
        }
    }

    /// Clears the pair after a successful login.
    pub fn record_success(&self, username: &str, ip: &str) {
        if let Ok(mut map) = self.pairs.lock() {
            map.remove(&(username.to_owned(), ip.to_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_delay_below_the_threshold() {
        for n in 0..FREE_FAILURES {
            assert_eq!(wait_after(n), Duration::ZERO);
        }
    }

    #[test]
    fn delay_doubles_from_one_second_and_caps_at_sixty() {
        assert_eq!(wait_after(5), Duration::from_secs(1));
        assert_eq!(wait_after(6), Duration::from_secs(2));
        assert_eq!(wait_after(7), Duration::from_secs(4));
        assert_eq!(wait_after(10), Duration::from_secs(32));
        assert_eq!(wait_after(11), Duration::from_secs(60));
        assert_eq!(wait_after(500), Duration::from_secs(60));
        assert_eq!(wait_after(u32::MAX), Duration::from_secs(60));
    }

    #[test]
    fn attempt_inside_the_wait_is_blocked_and_after_it_is_allowed() {
        let t = LoginThrottle::new();
        let start = Instant::now();
        for _ in 0..FREE_FAILURES {
            t.record_failure("test-user", "192.0.2.10", start);
        }
        // Fifth failure: the next attempt waits 1 second.
        assert!(t.is_blocked("test-user", "192.0.2.10", start));
        assert!(t.is_blocked(
            "test-user",
            "192.0.2.10",
            start + Duration::from_millis(500)
        ));
        assert!(!t.is_blocked("test-user", "192.0.2.10", start + Duration::from_secs(2)));
    }

    #[test]
    fn same_account_from_another_ip_is_not_delayed() {
        let t = LoginThrottle::new();
        let start = Instant::now();
        for _ in 0..(FREE_FAILURES + 3) {
            t.record_failure("test-user", "192.0.2.10", start);
        }
        assert!(t.is_blocked("test-user", "192.0.2.10", start));
        assert!(!t.is_blocked("test-user", "198.51.100.7", start));
    }

    #[test]
    fn success_resets_the_pair() {
        let t = LoginThrottle::new();
        let start = Instant::now();
        for _ in 0..(FREE_FAILURES + 2) {
            t.record_failure("test-user", "192.0.2.10", start);
        }
        assert!(t.is_blocked("test-user", "192.0.2.10", start));
        t.record_success("test-user", "192.0.2.10");
        assert!(!t.is_blocked("test-user", "192.0.2.10", start));
    }
}
