//! Bounded retry for transient HTTP failures, plus a sleep that wakes on shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::contabo::HttpResponse;
use crate::error::Error;

/// Extra attempts after the first one for a transient failure.
pub const MAX_TRANSIENT_RETRIES: u32 = 3;
/// Longest single sleep, so a shutdown request is seen within this window.
pub const SLEEP_SLICE: Duration = Duration::from_millis(50);

/// Shutdown flag that is never set, for callers without a signal handler.
pub static NO_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// True for statuses that are worth another attempt (rate limit and server errors).
pub fn retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

/// Whether `result` should be attempted again.
///
/// A 429 means the server refused the request before acting on it, so any method may
/// retry. A 5xx or transport error can follow a request that already took effect, so
/// only idempotent requests retry those.
fn should_retry(result: &Result<HttpResponse, Error>, idempotent: bool) -> bool {
    match result {
        Ok(response) => response.status == 429 || (idempotent && retryable_status(response.status)),
        Err(_) => idempotent,
    }
}

/// Runs `attempt` up to `MAX_TRANSIENT_RETRIES + 1` times, backing off between tries.
///
/// `delay` chooses the pause before attempt `retry` (0-based). Returns the last result.
/// Stops early when `shutdown` is set during a backoff.
pub fn send(
    label: &str,
    idempotent: bool,
    shutdown: &AtomicBool,
    delay: fn(u32) -> Duration,
    mut attempt: impl FnMut() -> Result<HttpResponse, Error>,
) -> Result<HttpResponse, Error> {
    let mut retries = 0;
    loop {
        let result = attempt();
        if retries >= MAX_TRANSIENT_RETRIES || !should_retry(&result, idempotent) {
            return result;
        }
        match &result {
            Ok(response) => log::warn!("{label} status {}, retrying", response.status),
            Err(err) => log::warn!("{label} failed, retrying: {err}"),
        }
        interruptible_sleep(delay(retries), shutdown);
        if shutdown.load(Ordering::Relaxed) {
            return result;
        }
        retries += 1;
    }
}

/// 1s, then 2s, then 4s. Later retries stay at 4s.
pub fn backoff(retry: u32) -> Duration {
    Duration::from_secs(1 << retry.min(2))
}

/// No pause. Test clients pass this so a retry does not wait on the clock.
#[cfg(test)]
pub fn immediate(_retry: u32) -> Duration {
    Duration::ZERO
}

/// Sleeps up to `delay` in `SLEEP_SLICE` steps, returning early once `shutdown` is set.
pub fn interruptible_sleep(delay: Duration, shutdown: &AtomicBool) {
    let start = Instant::now();
    while start.elapsed() < delay {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        thread::sleep(delay.saturating_sub(start.elapsed()).min(SLEEP_SLICE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(code: u16) -> Result<HttpResponse, Error> {
        Ok(HttpResponse {
            status: code,
            body: Vec::new(),
        })
    }

    fn count_attempts(
        idempotent: bool,
        shutdown: &AtomicBool,
        mut next: impl FnMut() -> Result<HttpResponse, Error>,
    ) -> (Result<HttpResponse, Error>, u32) {
        let mut attempts = 0;
        let result = send("GET /test", idempotent, shutdown, immediate, || {
            attempts += 1;
            next()
        });
        (result, attempts)
    }

    #[test]
    fn idempotent_requests_retry_server_and_transport_errors() {
        let (result, attempts) = count_attempts(true, &NO_SHUTDOWN, || status(503));
        assert_eq!(result.unwrap().status, 503);
        assert_eq!(attempts, MAX_TRANSIENT_RETRIES + 1);

        let (result, attempts) = count_attempts(true, &NO_SHUTDOWN, || Err(Error::new("reset")));
        assert!(result.is_err());
        assert_eq!(attempts, MAX_TRANSIENT_RETRIES + 1);

        let (result, attempts) = count_attempts(true, &NO_SHUTDOWN, || status(404));
        assert_eq!(result.unwrap().status, 404);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn non_idempotent_requests_retry_only_rate_limits() {
        let (result, attempts) = count_attempts(false, &NO_SHUTDOWN, || status(503));
        assert_eq!(result.unwrap().status, 503);
        assert_eq!(attempts, 1);

        let (result, attempts) = count_attempts(false, &NO_SHUTDOWN, || Err(Error::new("reset")));
        assert!(result.is_err());
        assert_eq!(attempts, 1);

        let mut codes = vec![200, 429];
        let (result, attempts) =
            count_attempts(false, &NO_SHUTDOWN, || status(codes.pop().unwrap()));
        assert_eq!(result.unwrap().status, 200);
        assert_eq!(attempts, 2);
    }

    #[test]
    fn shutdown_stops_retrying() {
        let shutdown = AtomicBool::new(true);
        let (result, attempts) = count_attempts(true, &shutdown, || status(500));
        assert_eq!(result.unwrap().status, 500);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn interruptible_sleep_waits_or_stops() {
        let start = Instant::now();
        interruptible_sleep(Duration::from_millis(60), &NO_SHUTDOWN);
        assert!(start.elapsed() >= Duration::from_millis(60));

        let start = Instant::now();
        interruptible_sleep(Duration::from_secs(5), &AtomicBool::new(true));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn backoff_doubles_then_caps_at_four_seconds() {
        assert_eq!(immediate(2), Duration::ZERO);
        assert_eq!(backoff(0), Duration::from_secs(1));
        assert_eq!(backoff(1), Duration::from_secs(2));
        assert_eq!(backoff(2), Duration::from_secs(4));
        assert_eq!(backoff(9), Duration::from_secs(4));
    }

    #[test]
    fn retryable_statuses() {
        assert!(retryable_status(429));
        assert!(retryable_status(502));
        assert!(!retryable_status(404));
        assert!(!retryable_status(600));
    }
}
