//! CSAT — one satisfaction survey per resolved ticket (migration 035).
//!
//! When a ticket is resolved, the requester gets one-click rating links
//! carrying an unguessable token. The row is created at send time, so the
//! token exists before the email does; only the first response is recorded — a
//! survey is not a poll, and a forwarded email must not rewrite the score.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Scores run 1..=5. Held as a constant so the mailer, the endpoint, and the
/// analytics page cannot disagree about the scale.
pub const CSAT_MIN: i64 = 1;
pub const CSAT_MAX: i64 = 5;

/// One survey, sent and possibly answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsatResponse {
    /// UUID.
    pub id: String,
    pub ticket_id: String,
    /// Unguessable; the whole authentication of the rating link.
    pub token: String,
    /// `None` until the requester clicks.
    pub score: Option<i64>,
    pub sent_at: DateTime<Utc>,
    pub responded_at: Option<DateTime<Utc>>,
}

/// Aggregate for the analytics page.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsatStats {
    /// Surveys sent.
    pub sent: i64,
    /// Surveys answered.
    pub responded: i64,
    /// Mean of the answered scores, `None` when nothing has been answered —
    /// an absent average is honest where 0.0 would read as catastrophe.
    pub average: Option<f64>,
}

/// Whether a submitted score is on the scale.
pub fn valid_score(score: i64) -> bool {
    (CSAT_MIN..=CSAT_MAX).contains(&score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_scores_on_the_scale_are_valid() {
        assert!(!valid_score(0));
        assert!(valid_score(1));
        assert!(valid_score(5));
        assert!(!valid_score(6));
        assert!(!valid_score(-3));
    }
}
