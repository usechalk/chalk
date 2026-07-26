//! Shared pagination types for the asset/device repositories.
//!
//! These exist because `console/src/lib.rs`'s user listing fetches every row
//! and filters in Rust. At 20k devices that is fatal, so every `list_*` method
//! on [`AssetRepository`](crate::db::repository::AssetRepository) and friends
//! takes a [`PageRequest`] that is pushed all the way into `LIMIT`/`OFFSET`,
//! and filtering happens in SQL, never in a `Vec::retain`.

use serde::{Deserialize, Serialize};

/// Largest page a caller may request. A caller asking for more is clamped
/// rather than rejected — an oversized `limit` is a UI bug, not a reason to
/// fail an inventory listing.
pub const MAX_PAGE_LIMIT: i64 = 500;

/// Page size used when a caller does not specify one.
pub const DEFAULT_PAGE_LIMIT: i64 = 50;

/// A `LIMIT`/`OFFSET` window. Construct with [`PageRequest::new`], which
/// clamps both fields into range — the raw fields are always safe to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    limit: i64,
    offset: i64,
}

impl PageRequest {
    /// Clamp `limit` to `1..=MAX_PAGE_LIMIT` and `offset` to `>= 0`.
    pub fn new(limit: i64, offset: i64) -> Self {
        Self {
            limit: limit.clamp(1, MAX_PAGE_LIMIT),
            offset: offset.max(0),
        }
    }

    /// A page window from a 1-based page number.
    pub fn from_page_number(page: i64, per_page: i64) -> Self {
        let per_page = per_page.clamp(1, MAX_PAGE_LIMIT);
        Self::new(per_page, (page.max(1) - 1) * per_page)
    }

    pub fn limit(&self) -> i64 {
        self.limit
    }

    pub fn offset(&self) -> i64 {
        self.offset
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self::new(DEFAULT_PAGE_LIMIT, 0)
    }
}

/// One page of rows plus the total row count matching the same filter, so a
/// caller can render "showing 51–100 of 4,312" without a second round trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Total rows matching the filter, ignoring `LIMIT`/`OFFSET`.
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, total: i64, request: PageRequest) -> Self {
        Self {
            items,
            total,
            limit: request.limit(),
            offset: request.offset(),
        }
    }

    /// True when another page exists after this one.
    pub fn has_more(&self) -> bool {
        self.offset + (self.items.len() as i64) < self.total
    }

    /// Offset of the next page, or `None` when this is the last one.
    pub fn next_offset(&self) -> Option<i64> {
        if self.has_more() {
            Some(self.offset + self.limit)
        } else {
            None
        }
    }
}

/// Sort direction for a whitelisted sort column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

impl SortDirection {
    /// Literal SQL keyword. Never interpolate anything but this — the value is
    /// a closed enum precisely so the sort clause cannot carry user input.
    pub fn as_sql(&self) -> &'static str {
        match self {
            SortDirection::Asc => "ASC",
            SortDirection::Desc => "DESC",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_is_clamped_into_range() {
        assert_eq!(PageRequest::new(0, 0).limit(), 1);
        assert_eq!(PageRequest::new(-5, 0).limit(), 1);
        assert_eq!(PageRequest::new(10_000, 0).limit(), MAX_PAGE_LIMIT);
        assert_eq!(PageRequest::new(25, 0).limit(), 25);
    }

    #[test]
    fn negative_offset_becomes_zero() {
        assert_eq!(PageRequest::new(10, -3).offset(), 0);
    }

    #[test]
    fn page_number_is_one_based() {
        assert_eq!(PageRequest::from_page_number(1, 20).offset(), 0);
        assert_eq!(PageRequest::from_page_number(3, 20).offset(), 40);
        // Page 0 and page 1 are the same page rather than an error.
        assert_eq!(PageRequest::from_page_number(0, 20).offset(), 0);
    }

    #[test]
    fn default_is_first_page() {
        let d = PageRequest::default();
        assert_eq!((d.limit(), d.offset()), (DEFAULT_PAGE_LIMIT, 0));
    }

    #[test]
    fn has_more_reflects_total() {
        let req = PageRequest::new(2, 0);
        let full = Page::new(vec![1, 2], 5, req);
        assert!(full.has_more());
        assert_eq!(full.next_offset(), Some(2));

        let last = Page::new(vec![9], 5, PageRequest::new(2, 4));
        assert!(!last.has_more());
        assert_eq!(last.next_offset(), None);
    }

    #[test]
    fn empty_page_at_end_has_no_more() {
        let empty: Page<i32> = Page::new(vec![], 5, PageRequest::new(2, 6));
        assert!(!empty.has_more());
    }

    #[test]
    fn sort_direction_sql_is_a_closed_set() {
        assert_eq!(SortDirection::Asc.as_sql(), "ASC");
        assert_eq!(SortDirection::Desc.as_sql(), "DESC");
    }
}
