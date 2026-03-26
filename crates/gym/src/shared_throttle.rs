//! Cross-process adaptive rate controller using a memory-mapped shared file.
//!
//! Multiple `gym eval` shard processes coordinate API rate limiting through
//! a shared file at a well-known path. The file contains atomic counters
//! for successes, rate-limit errors, and a retry-after timestamp.
//!
//! AIMD (Additive Increase, Multiplicative Decrease) congestion control:
//! - When all processes report success: increase concurrency
//! - When any process gets rate-limited: ALL processes back off
//! - Retry-after from API is respected globally

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Layout of the shared memory region (64 bytes, cache-line aligned).
#[repr(C, align(64))]
struct SharedState {
    /// Current allowed concurrency per process (AIMD-controlled).
    concurrency: AtomicU32,
    /// Successes in the current window.
    window_successes: AtomicU32,
    /// Rate-limit errors in the current window.
    window_rate_errors: AtomicU32,
    /// Other errors in the current window.
    window_other_errors: AtomicU32,
    /// Unix timestamp (secs) when rate limit expires. 0 = no active limit.
    retry_after_epoch: AtomicU64,
    /// Number of active processes sharing this controller.
    active_processes: AtomicU32,
    /// Window start epoch (secs).
    window_start_epoch: AtomicU64,
    /// Padding to fill 64 bytes.
    _pad: AtomicU32,
}

const SHARED_STATE_SIZE: usize = std::mem::size_of::<SharedState>();
const _: () = assert!(SHARED_STATE_SIZE <= 64);

/// Default path for the shared throttle file.
fn default_path() -> PathBuf {
    std::env::temp_dir().join("skwaq-gym-throttle.mmap")
}

/// Cross-process rate controller backed by a memory-mapped file.
pub struct SharedRateController {
    _file: File,
    mmap: memmap2::MmapMut,
    min_concurrency: u32,
    max_concurrency: u32,
}

impl SharedRateController {
    /// Open or create the shared rate controller at the default path.
    pub fn open_default(
        initial_concurrency: u32,
        min_concurrency: u32,
        max_concurrency: u32,
    ) -> io::Result<Self> {
        Self::open(
            &default_path(),
            initial_concurrency,
            min_concurrency,
            max_concurrency,
        )
    }

    /// Open or create the shared rate controller at a specific path.
    pub fn open(
        path: &Path,
        initial_concurrency: u32,
        min_concurrency: u32,
        max_concurrency: u32,
    ) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        // Ensure file is large enough.
        let meta = file.metadata()?;
        if meta.len() < SHARED_STATE_SIZE as u64 {
            file.set_len(SHARED_STATE_SIZE as u64)?;
        }

        // Safety: the file is sized to hold SharedState and we use atomics for all access.
        let mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };

        let controller = Self {
            _file: file,
            mmap,
            min_concurrency,
            max_concurrency,
        };

        // Initialize if this is the first process (concurrency == 0).
        let state = controller.state();
        if state.concurrency.load(Ordering::Relaxed) == 0 {
            state
                .concurrency
                .store(initial_concurrency, Ordering::Release);
            let now = now_epoch();
            state.window_start_epoch.store(now, Ordering::Release);
        }
        state.active_processes.fetch_add(1, Ordering::Release);

        Ok(controller)
    }

    fn state(&self) -> &SharedState {
        // Safety: mmap is at least SHARED_STATE_SIZE bytes, SharedState uses atomics.
        unsafe { &*(self.mmap.as_ptr() as *const SharedState) }
    }

    /// Record a successful API call.
    pub fn record_success(&self) {
        let state = self.state();
        state.window_successes.fetch_add(1, Ordering::Relaxed);
        self.maybe_adjust();
    }

    /// Record a rate-limited response (HTTP 429).
    /// If `retry_after_secs` is provided, sets the global backoff.
    pub fn record_rate_limit(&self, retry_after_secs: Option<u64>) {
        let state = self.state();
        state.window_rate_errors.fetch_add(1, Ordering::Relaxed);

        if let Some(secs) = retry_after_secs {
            let deadline = now_epoch() + secs;
            // Only extend the deadline, never shorten it.
            state
                .retry_after_epoch
                .fetch_max(deadline, Ordering::Release);
        }

        // Immediate multiplicative decrease.
        let current = state.concurrency.load(Ordering::Relaxed);
        let new = (current / 2).max(self.min_concurrency);
        state.concurrency.store(new, Ordering::Release);

        self.maybe_adjust();
    }

    /// Record a non-rate-limit error.
    pub fn record_error(&self) {
        let state = self.state();
        state.window_other_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current allowed concurrency. Returns 0 if we should pause
    /// (rate limit retry-after is still active).
    pub fn concurrency(&self) -> u32 {
        let state = self.state();
        let deadline = state.retry_after_epoch.load(Ordering::Acquire);
        if deadline > 0 && now_epoch() < deadline {
            return 0; // Paused — respect retry-after.
        }
        // Clear expired deadline.
        if deadline > 0 && now_epoch() >= deadline {
            state.retry_after_epoch.store(0, Ordering::Release);
        }
        state.concurrency.load(Ordering::Acquire)
    }

    /// Check if we're currently in a global backoff period.
    pub fn is_paused(&self) -> bool {
        let state = self.state();
        let deadline = state.retry_after_epoch.load(Ordering::Acquire);
        deadline > 0 && now_epoch() < deadline
    }

    /// Seconds until retry-after expires. 0 if not paused.
    pub fn pause_remaining_secs(&self) -> u64 {
        let state = self.state();
        let deadline = state.retry_after_epoch.load(Ordering::Acquire);
        if deadline > 0 {
            deadline.saturating_sub(now_epoch())
        } else {
            0
        }
    }

    /// Wait until the rate limit expires, then return the new concurrency.
    pub async fn wait_for_resume(&self) -> u32 {
        let remaining = self.pause_remaining_secs();
        if remaining > 0 {
            tracing::info!(
                "Shared rate controller: paused for {}s (retry-after)",
                remaining
            );
            tokio::time::sleep(std::time::Duration::from_secs(remaining)).await;
        }
        self.concurrency()
    }

    /// Get stats for logging/monitoring.
    pub fn stats(&self) -> SharedThrottleStats {
        let state = self.state();
        SharedThrottleStats {
            concurrency: state.concurrency.load(Ordering::Relaxed),
            window_successes: state.window_successes.load(Ordering::Relaxed),
            window_rate_errors: state.window_rate_errors.load(Ordering::Relaxed),
            window_other_errors: state.window_other_errors.load(Ordering::Relaxed),
            active_processes: state.active_processes.load(Ordering::Relaxed),
            paused: self.is_paused(),
            pause_remaining_secs: self.pause_remaining_secs(),
        }
    }

    /// AIMD window adjustment — called after each record.
    fn maybe_adjust(&self) {
        let state = self.state();
        let window_start = state.window_start_epoch.load(Ordering::Relaxed);
        let now = now_epoch();
        let window_secs = 30;

        if now - window_start < window_secs {
            return; // Window not yet expired.
        }

        // Reset window.
        state.window_start_epoch.store(now, Ordering::Release);
        let successes = state.window_successes.swap(0, Ordering::Relaxed);
        let rate_errors = state.window_rate_errors.swap(0, Ordering::Relaxed);
        let _other_errors = state.window_other_errors.swap(0, Ordering::Relaxed);
        let total = successes + rate_errors;

        if total == 0 {
            return;
        }

        let error_rate = rate_errors as f64 / total as f64;
        let current = state.concurrency.load(Ordering::Relaxed);

        let new = if error_rate < 0.05 {
            // Low errors: additive increase.
            (current + 1).min(self.max_concurrency)
        } else if error_rate > 0.20 {
            // High errors: multiplicative decrease.
            (current / 2).max(self.min_concurrency)
        } else {
            current
        };

        if new != current {
            state.concurrency.store(new, Ordering::Release);
            tracing::info!(
                "Shared rate controller: concurrency {} -> {} (error_rate={:.1}%, window: {} success, {} rate_limit)",
                current,
                new,
                error_rate * 100.0,
                successes,
                rate_errors
            );
        }
    }
}

impl Drop for SharedRateController {
    fn drop(&mut self) {
        let state = self.state();
        state.active_processes.fetch_sub(1, Ordering::Release);
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Stats snapshot from the shared rate controller.
#[derive(Debug, Clone)]
pub struct SharedThrottleStats {
    pub concurrency: u32,
    pub window_successes: u32,
    pub window_rate_errors: u32,
    pub window_other_errors: u32,
    pub active_processes: u32,
    pub paused: bool,
    pub pause_remaining_secs: u64,
}

impl std::fmt::Display for SharedThrottleStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "concurrency={} procs={} ok={} rate_err={} paused={}",
            self.concurrency,
            self.active_processes,
            self.window_successes,
            self.window_rate_errors,
            if self.paused {
                format!("{}s", self.pause_remaining_secs)
            } else {
                "no".into()
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_state_fits_cache_line() {
        // Verified at compile time by const assert at module level.
        // This test exists for documentation.
        let _ = SHARED_STATE_SIZE;
    }

    #[test]
    fn test_open_and_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("throttle.mmap");
        let ctrl = SharedRateController::open(&path, 4, 1, 16).unwrap();
        assert_eq!(ctrl.concurrency(), 4);

        ctrl.record_success();
        ctrl.record_success();
        let stats = ctrl.stats();
        assert_eq!(stats.window_successes, 2);
        assert_eq!(stats.active_processes, 1);
        assert!(!stats.paused);
    }

    #[test]
    fn test_rate_limit_pauses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("throttle.mmap");
        let ctrl = SharedRateController::open(&path, 4, 1, 16).unwrap();

        ctrl.record_rate_limit(Some(5));
        assert!(ctrl.is_paused());
        assert_eq!(ctrl.concurrency(), 0);
        // Concurrency was halved: 4 -> 2.
        let stats = ctrl.stats();
        assert_eq!(stats.concurrency, 2);
    }

    #[test]
    fn test_multi_process_sharing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("throttle.mmap");

        let ctrl1 = SharedRateController::open(&path, 4, 1, 16).unwrap();
        let ctrl2 = SharedRateController::open(&path, 4, 1, 16).unwrap();

        assert_eq!(ctrl1.stats().active_processes, 2);
        assert_eq!(ctrl2.stats().active_processes, 2);

        // Process 1 records rate limit — process 2 should see the backoff.
        ctrl1.record_rate_limit(Some(10));
        assert!(ctrl2.is_paused());
        assert_eq!(ctrl2.stats().concurrency, 2); // Halved from 4.
    }
}
