//! Knowledge-base articles (migration 036).
//!
//! An article IT writes once instead of answering the same question forever.
//! Drafts live in the console only. Published articles are readable on the
//! staff help portal without any sign-in, because nothing in them is personal —
//! requiring a session to read "how to join the wifi" would defeat the point.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One article.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KbArticle {
    /// UUID.
    pub id: String,
    pub title: String,
    /// Plain text, paragraphs preserved. Deliberately not markdown: the
    /// authors are technicians in a hurry, and text that renders exactly as
    /// typed cannot surprise them.
    pub body: String,
    pub published: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl KbArticle {
    /// A new draft. Publishing is a separate, deliberate act.
    pub fn draft(id: impl Into<String>, title: impl Into<String>, body: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            title: title.into(),
            body: body.into(),
            published: false,
            created_at: now,
            updated_at: now,
        }
    }
}
