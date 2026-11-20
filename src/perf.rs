// SPDX-License-Identifier: GPL-3.0-only

//! Opt-in slow-frame logger.
//!
//! Set `COSMIC_FILES_PERF=1` to log every `update`/`view` call that takes
//! longer than [`threshold`] (default 8 ms, override with
//! `COSMIC_FILES_PERF_MS=<n>`). Disabled, a [`Timer`] costs one atomic load.

use std::fmt::{self, Write};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

static THRESHOLD: LazyLock<Option<Duration>> = LazyLock::new(|| {
    let enabled = std::env::var("COSMIC_FILES_PERF").is_ok_and(|v| !v.is_empty() && v != "0");
    enabled.then(|| {
        let ms = std::env::var("COSMIC_FILES_PERF_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(8);
        Duration::from_millis(ms)
    })
});

/// Slow-call threshold, or `None` when the logger is disabled.
pub fn threshold() -> Option<Duration> {
    *THRESHOLD
}

/// Drop guard that logs `label` (and `detail`) if it lived longer than the threshold.
pub struct Timer {
    start: Instant,
    threshold: Duration,
    label: &'static str,
    detail: String,
}

impl Timer {
    /// Starts a timer when the logger is enabled. `detail` is only evaluated then.
    pub fn start(label: &'static str, detail: impl FnOnce() -> String) -> Option<Self> {
        threshold().map(|threshold| Self {
            start: Instant::now(),
            threshold,
            label,
            detail: detail(),
        })
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        if elapsed >= self.threshold {
            log::warn!(
                "perf: slow {} {:.1} ms {}",
                self.label,
                elapsed.as_secs_f64() * 1000.0,
                self.detail
            );
        }
    }
}

/// `Debug`-formats `value`, stopping after `max` bytes so large payloads stay cheap.
pub fn debug_prefix(value: &impl fmt::Debug, max: usize) -> String {
    struct Bounded {
        buf: String,
        max: usize,
    }
    impl Write for Bounded {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let room = self.max.saturating_sub(self.buf.len());
            if s.len() <= room {
                self.buf.push_str(s);
                Ok(())
            } else {
                let mut end = room;
                while !s.is_char_boundary(end) {
                    end -= 1;
                }
                self.buf.push_str(&s[..end]);
                Err(fmt::Error)
            }
        }
    }
    let mut w = Bounded {
        buf: String::new(),
        max,
    };
    if write!(w, "{value:?}").is_err() {
        w.buf.push('…');
    }
    w.buf
}

#[cfg(test)]
mod tests {
    use super::debug_prefix;

    #[test]
    fn debug_prefix_truncates() {
        assert_eq!(debug_prefix(&"ab", 10), "\"ab\"");
        assert_eq!(debug_prefix(&vec![1, 2, 3, 4, 5], 4), "[1, …");
    }
}
