//! Canned responses — shared reply templates for the help desk (migration 030).
//!
//! A technician answers the same handful of questions all day. A canned
//! response is a titled block of text the reply box can be filled from, so the
//! wording stays consistent and the typing stops. They are district-wide on
//! purpose: the value is a shared voice, and a per-technician library is a later
//! refinement if anyone asks for it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A saved reply template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CannedResponse {
    /// UUID.
    pub id: String,
    /// What the technician picks it by, in the dropdown.
    pub title: String,
    /// The text that fills the reply box.
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CannedResponse {
    /// A new response with timestamps stamped now.
    pub fn new(id: impl Into<String>, title: impl Into<String>, body: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            title: title.into(),
            body: body.into(),
            created_at: now,
            updated_at: now,
        }
    }
}
