//! Saved queue views — named bookmarks over the ticket queue (migration 033).
//!
//! The queue's state already round-trips through its URL query string, so a
//! saved view stores exactly that: the name a technician gave it and the query
//! it reproduces. Nothing here interprets the string — the queue's own parser
//! is the single authority on what it means, so a saved view can never drift
//! from what filtering actually does.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A named bookmark over the ticket queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedView {
    /// UUID.
    pub id: String,
    /// What the picker shows.
    pub name: String,
    /// The queue's own query string, without the leading `?`.
    pub query_string: String,
    pub created_at: DateTime<Utc>,
}

impl SavedView {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        query_string: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            query_string: query_string.into(),
            created_at: Utc::now(),
        }
    }
}
