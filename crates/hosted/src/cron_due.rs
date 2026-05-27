//! Cron-schedule "is it due?" helper.
//!
//! The hosted scheduler ticks every ~60s and asks, for each tenant + engine
//! pair (SIS, Google Sync, AD Sync): given this cron expression and the
//! timestamp of the last successful or failed run, should we dispatch the
//! engine *now*?
//!
//! Semantics: a schedule "fires" at the cron expression's discrete points
//! in time. If the most recent fire-time is after the last recorded run,
//! we dispatch. If we somehow miss a tick (the scheduler was paused, the
//! tenant was suspended, etc.), the next tick still treats the most recent
//! fire as due — so we coalesce missed ticks into one run rather than
//! firing N times to "catch up".

use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use cron::Schedule;

/// Accept both the classic POSIX 5-field cron (`min hour dom month dow`) and
/// the 6-field "with seconds" form the `cron` crate expects. The TOML
/// examples + every default in `chalk_core::config` use the 5-field form,
/// so we prefix `0 ` (seconds = 0) when only 5 whitespace-separated tokens
/// are present.
fn normalize_cron(expr: &str) -> String {
    let token_count = expr.split_whitespace().count();
    if token_count == 5 {
        format!("0 {}", expr.trim())
    } else {
        expr.to_string()
    }
}

/// Is the cron expression `expression` due to fire at `now`, given the
/// previous run started at `last_run`?
///
/// Behavior:
/// - `None` `last_run` is treated as "never ran" → due as soon as the cron
///   expression has *any* fire time in the recent past.
/// - Malformed `expression` returns `false` (we don't want a typo'd
///   schedule to silently spam syncs).
/// - We look back up to 24h. A schedule that fires less often than once
///   per day (e.g. `0 2 1 * *` — first of every month) still works because
///   `last_run` carries forward; the lookback bound is just a guard
///   against `Schedule::after` iterating far into the past on first call.
pub fn cron_due(expression: &str, last_run: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    let schedule = match Schedule::from_str(&normalize_cron(expression)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let lookback = Duration::days(1);
    let start = last_run.unwrap_or_else(|| now - lookback);
    // Bound the iterator: if last_run is older than 24h we cap at now-24h
    // so `Schedule::after` doesn't churn through a year of skipped fires.
    let start = start.max(now - lookback);
    schedule
        .after(&start)
        .next()
        .map(|next| next <= now)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, 0)
            .unwrap()
    }

    #[test]
    fn malformed_expression_is_never_due() {
        let now = ts(2026, 5, 27, 12, 0);
        assert!(!cron_due("not a cron", None, now));
        assert!(!cron_due("", None, now));
        assert!(!cron_due("* * *", None, now));
    }

    #[test]
    fn first_run_uses_recent_past_lookback() {
        // `0 0 2 * * *` = at 02:00:00 every day (cron crate uses 6-field
        // `sec min hour dom month dow`). With no prior run, the most
        // recent fire within the 24h lookback window is yesterday or today
        // 02:00 — so noon today should be "due" (we missed the 02:00 fire).
        let now = ts(2026, 5, 27, 12, 0);
        assert!(cron_due("0 0 2 * * *", None, now));
    }

    #[test]
    fn already_ran_after_most_recent_fire_is_not_due() {
        // Cron fired at 02:00; we ran at 02:01; now is noon.
        let last = ts(2026, 5, 27, 2, 1);
        let now = ts(2026, 5, 27, 12, 0);
        assert!(!cron_due("0 0 2 * * *", Some(last), now));
    }

    #[test]
    fn ran_before_most_recent_fire_is_due() {
        // We ran yesterday at noon; cron fires daily at 02:00; now is 03:00
        // today — the 02:00 fire is more recent than our run.
        let last = ts(2026, 5, 26, 12, 0);
        let now = ts(2026, 5, 27, 3, 0);
        assert!(cron_due("0 0 2 * * *", Some(last), now));
    }

    #[test]
    fn six_field_expressions_accepted() {
        // The `cron` crate uses 6 fields (`sec min hour dom month dow`).
        // Pin the spec we expect with an explicit assertion.
        let now = ts(2026, 5, 27, 12, 0);
        assert!(cron_due("0 0 2 * * *", None, now));
    }

    #[test]
    fn five_field_expressions_normalized_with_zero_seconds() {
        // POSIX-style `0 2 * * *` = at 02:00 every day. We auto-prefix
        // `0 ` so this resolves to the same fires as `0 0 2 * * *`.
        let now = ts(2026, 5, 27, 12, 0);
        assert!(cron_due("0 2 * * *", None, now));
    }

    #[test]
    fn very_old_last_run_is_due_once_not_thrice() {
        // Schedule that fires hourly (at minute 0). Last run was a month
        // ago. We should dispatch *once* now — not 30*24 times — because
        // the 24h lookback bounds the catch-up window.
        let last = ts(2026, 4, 27, 12, 0);
        let now = ts(2026, 5, 27, 12, 0);
        // Hourly at minute 0: 0 0 * * * *
        assert!(cron_due("0 0 * * * *", Some(last), now));
    }
}
