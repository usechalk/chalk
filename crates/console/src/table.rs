//! The dense-data-table primitives (DESIGN_SYSTEM.md §5.3–§5.5), shared by
//! every list page rather than owned by any one of them.
//!
//! Devices is the first consumer. Users, webhooks and SSO partners adopt it by
//! doing three things:
//!
//! 1. Define a query struct with `#[serde(default)]` fields, and translate it
//!    into the domain filter plus a [`PageRequest`].
//! 2. Build a [`TableNav`] from the canonical filter pairs, the sort, the page
//!    and the total. Everything structural — sort links, `aria-sort`, page
//!    links, the result summary, the page-size switcher — comes off it.
//! 3. Render `partials/table.html`'s macros around a `<tbody>` of their own.
//!    The body is the only genuinely type-specific part of a table, and Askama
//!    templates are not generic, so that is where the reuse boundary sits.
//!
//! # Why the query string is the state
//!
//! Sorting, filtering and paging are all URL state, pushed with `hx-push-url`,
//! because §5.4's saved views are literally URLs. That makes every link here a
//! real `href` that works with JavaScript disabled; HTMX only intercepts it to
//! swap a region instead of the document.
//!
//! # Why selection is filter-scoped
//!
//! See [`Selection`]. This is the part that is easy to get subtly, dangerously
//! wrong, and the reasoning lives with the code.

use std::fmt::Write as _;

use chalk_core::models::page::PageRequest;

/// Page sizes offered in the toolbar (§5.5). Anything else in the URL is
/// snapped to the nearest of these rather than rejected — an odd `per_page` is
/// a stale bookmark, not an attack.
pub const PAGE_SIZES: [i64; 3] = [50, 100, 250];

/// Default rows per page. §5.3's compact density defaults to 100.
pub const DEFAULT_PAGE_SIZE: i64 = 100;

/// Length of the hex filter-scope digest. 16 hex chars is 64 bits — far more
/// than needed to notice a filter changing under an operator.
const FILTER_HASH_LEN: usize = 16;

/// Clamp a requested page size onto [`PAGE_SIZES`].
///
/// Snaps rather than rejects: a bookmarked `?per_page=75` should still render
/// devices. Snapping down is deliberate — the failure mode of guessing high is
/// a slow page, and of guessing low is one extra click.
pub fn clamp_page_size(requested: Option<i64>) -> i64 {
    let Some(requested) = requested else {
        return DEFAULT_PAGE_SIZE;
    };
    let mut best = PAGE_SIZES[0];
    for size in PAGE_SIZES {
        if size <= requested {
            best = size;
        }
    }
    best
}

/// Canonical, stable rendering of the active filter.
///
/// Pairs are sorted by key and empty values dropped, so two URLs that mean the
/// same filter produce the same string — and therefore the same
/// [`filter_hash`]. Without that, `?status=repair&school=hs` and
/// `?school=hs&status=repair` would be two different selection scopes.
pub fn canonical_filter(pairs: &[(String, String)]) -> String {
    let mut kept: Vec<&(String, String)> = pairs.iter().filter(|(_, v)| !v.is_empty()).collect();
    kept.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut out = String::new();
    for (i, (k, v)) in kept.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        let _ = write!(out, "{}={}", urlencoding::encode(k), urlencoding::encode(v));
    }
    out
}

/// Digest of a [`canonical_filter`] string, carried on the bulk form.
///
/// **This is an integrity token, not an authorization token.** It is unkeyed,
/// so it proves only that the filter the form carries is the filter the page
/// rendered — it does not stop anyone from submitting a different filter, and
/// it must not be treated as if it did. Every bulk endpoint re-derives the
/// matching set from the submitted filter server-side and re-counts it.
///
/// What it buys is the failure that actually happens: an operator leaves a
/// filtered page open, the fleet changes underneath them, and the write lands
/// on a different set than the one they read. Pairing the hash with the
/// displayed match count lets the server refuse rather than guess.
pub fn filter_hash(canonical: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    digest[..FILTER_HASH_LEN].to_string()
}

/// Which rows a bulk action applies to.
///
/// Chromebook Getter pulls a district's whole fleet into one spreadsheet, so
/// "filter to 400 rows, press the button" acts on all 400 — its users are
/// trained on *what you can see is what will be written*. A web table shows one
/// page of 100. Copying the idiom naively means a technician who filters to 400
/// and hits an action gets 100, or worse believes they got 400.
///
/// So the default scope is the **filter**, never the page. The bulk bar reads
/// "400 devices match this filter", the form carries the filter and its hash
/// rather than 400 ids, and picking individual rows is a visibly distinct
/// second mode whose count always says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionMode {
    /// Every row matching the active filter, however many pages that spans.
    #[default]
    Matching,
    /// Only the rows whose checkboxes are ticked, which live on this page.
    Picked,
}

impl SelectionMode {
    /// The wire value carried in the form's `selection_mode` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            SelectionMode::Matching => "matching",
            SelectionMode::Picked => "picked",
        }
    }

    /// Parse a wire value, defaulting to the filter-scoped mode. An unknown
    /// value must never silently become the narrower scope: a bulk action that
    /// quietly does less than the operator asked is the trap this whole type
    /// exists to close.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "picked" => SelectionMode::Picked,
            _ => SelectionMode::Matching,
        }
    }
}

/// What the bulk bar carries on the wire, and what the template renders.
#[derive(Debug, Clone)]
pub struct Selection {
    pub mode: SelectionMode,
    /// The canonical filter this scope was computed against.
    pub filter: String,
    /// [`filter_hash`] of `filter`.
    pub filter_hash: String,
    /// Rows matching `filter` across all pages, as displayed to the operator.
    pub match_count: i64,
    /// Rows on the page currently being rendered.
    pub page_count: i64,
}

impl Selection {
    pub fn new(
        mode: SelectionMode,
        filter_pairs: &[(String, String)],
        match_count: i64,
        page_count: i64,
    ) -> Self {
        let filter = canonical_filter(filter_pairs);
        let filter_hash = filter_hash(&filter);
        Self {
            mode,
            filter,
            filter_hash,
            match_count,
            page_count,
        }
    }

    /// True when the filter spans more rows than the page shows — the exact
    /// condition under which "what you can see" and "what will be written"
    /// diverge, and therefore the condition the copy has to address head-on.
    pub fn spans_more_than_a_page(&self) -> bool {
        self.match_count > self.page_count
    }

    /// True when a filter is actually narrowing the table.
    pub fn is_filtered(&self) -> bool {
        !self.filter.is_empty()
    }

    pub fn is_matching(&self) -> bool {
        self.mode == SelectionMode::Matching
    }

    /// The sentence in the bulk bar, in filter scope.
    ///
    /// It says "match this filter" rather than "selected" deliberately. A bar
    /// reading "100 selected" on a 400-row filter is the trap: it is true of
    /// the page and false of the intent. Naming the *scope* rather than a
    /// count of checkboxes is what keeps the two from being confused.
    pub fn scope_sentence(&self, singular: &str, plural: &str) -> String {
        let noun = if self.match_count == 1 {
            singular
        } else {
            plural
        };
        let verb = if self.match_count == 1 {
            "matches"
        } else {
            "match"
        };
        if self.is_filtered() {
            format!("{} {noun} {verb} this filter", thousands(self.match_count))
        } else {
            format!(
                "All {} {noun} in the inventory",
                thousands(self.match_count)
            )
        }
    }

    /// Spelled out whenever the scope is wider than what is on screen, so the
    /// difference between "what you can see" and "what will be written" is
    /// never left for the operator to infer.
    pub fn beyond_page_sentence(&self, plural: &str) -> String {
        if !self.spans_more_than_a_page() {
            return String::new();
        }
        format!(
            "including {} {plural} on other pages",
            thousands(self.match_count - self.page_count)
        )
    }
}

/// One entry in the pagination control.
#[derive(Debug, Clone)]
pub struct PageLink {
    pub number: i64,
    pub href: String,
    pub is_current: bool,
    /// A `…` placeholder rather than a real page. Rendered as text, never a
    /// link, and never focusable.
    pub is_gap: bool,
}

/// One page-size option in the toolbar.
#[derive(Debug, Clone)]
pub struct PageSizeOption {
    pub size: i64,
    pub href: String,
    pub is_current: bool,
}

/// Everything a dense table's chrome needs: sort links, `aria-sort` values,
/// pagination and the result summary.
///
/// Holds no rows and knows nothing about the domain — that is what makes it
/// shareable across list pages.
#[derive(Debug, Clone)]
pub struct TableNav {
    /// Route the table lives at, e.g. `/devices`.
    pub base_path: String,
    /// `id` of the swap target, e.g. `devices-region`.
    pub region_id: String,
    /// Canonical filter pairs, excluding sort/direction/paging.
    pub filter_pairs: Vec<(String, String)>,
    /// Currently sorted column key (an [`AssetSort`]-style closed value at the
    /// caller; a plain string here so the type stays domain-agnostic).
    ///
    /// [`AssetSort`]: chalk_core::models::asset::AssetSort
    pub sort: String,
    /// `"asc"` or `"desc"`.
    pub direction: String,
    /// 1-based.
    pub page: i64,
    pub per_page: i64,
    /// Rows matching the filter across all pages.
    pub total: i64,
}

impl TableNav {
    /// Build the URL for this table with the given overrides applied on top of
    /// the active filter. Values are percent-encoded; the filter pairs come
    /// from the caller's own parsed query, never from raw request text.
    fn href(&self, sort: &str, direction: &str, page: i64, per_page: i64) -> String {
        let mut pairs: Vec<(String, String)> = self
            .filter_pairs
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .cloned()
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        pairs.push(("sort".into(), sort.to_string()));
        pairs.push(("dir".into(), direction.to_string()));
        if per_page != DEFAULT_PAGE_SIZE {
            pairs.push(("per_page".into(), per_page.to_string()));
        }
        // Page 1 is the canonical bare URL, so a shared "first page" link is
        // the same string however the operator got there.
        if page > 1 {
            pairs.push(("page".into(), page.to_string()));
        }

        let mut out = self.base_path.clone();
        for (i, (k, v)) in pairs.iter().enumerate() {
            let _ = write!(
                out,
                "{}{}={}",
                if i == 0 { '?' } else { '&' },
                urlencoding::encode(k),
                urlencoding::encode(v)
            );
        }
        out
    }

    /// True when `column` is the one currently sorted.
    pub fn is_sorted_by(&self, column: &str) -> bool {
        self.sort == column
    }

    /// The `aria-sort` value for a header cell (WAI-ARIA: exactly one column
    /// in a grid may be `ascending`/`descending`).
    pub fn aria_sort(&self, column: &str) -> &'static str {
        if !self.is_sorted_by(column) {
            return "none";
        }
        if self.direction == "desc" {
            "descending"
        } else {
            "ascending"
        }
    }

    /// Link that sorts by `column`. Clicking the sorted column flips direction;
    /// clicking any other column starts ascending, which is what every
    /// spreadsheet does and therefore what a technician expects.
    ///
    /// Always returns to page 1: staying on page 7 of a re-sorted table shows
    /// rows the operator never asked for.
    pub fn sort_href(&self, column: &str) -> String {
        let next = if self.is_sorted_by(column) && self.direction == "asc" {
            "desc"
        } else {
            "asc"
        };
        self.href(column, next, 1, self.per_page)
    }

    /// The direction activating this header would sort in — the word that
    /// makes the link's accessible name describe its *action*.
    ///
    /// "Asset tag" as a link name fails WCAG 2.4.4 read out of context: it
    /// names the column, not what following the link does. `aria-sort` tells a
    /// screen-reader user the current state; this tells them what changes.
    pub fn next_direction_word(&self, column: &str) -> &'static str {
        if self.is_sorted_by(column) && self.direction == "asc" {
            "descending"
        } else {
            "ascending"
        }
    }

    /// A visible, non-colour cue for sort state. Screen readers get
    /// `aria-sort`; this is the sighted channel.
    pub fn sort_indicator(&self, column: &str) -> &'static str {
        if !self.is_sorted_by(column) {
            return "";
        }
        if self.direction == "desc" {
            "▾"
        } else {
            "▴"
        }
    }

    pub fn total_pages(&self) -> i64 {
        if self.total <= 0 {
            return 1;
        }
        (self.total + self.per_page - 1) / self.per_page
    }

    pub fn is_first_page(&self) -> bool {
        self.page <= 1
    }

    pub fn is_last_page(&self) -> bool {
        self.page >= self.total_pages()
    }

    pub fn prev_href(&self) -> String {
        self.href(
            &self.sort,
            &self.direction,
            (self.page - 1).max(1),
            self.per_page,
        )
    }

    pub fn next_href(&self) -> String {
        self.href(
            &self.sort,
            &self.direction,
            (self.page + 1).min(self.total_pages()),
            self.per_page,
        )
    }

    /// The canonical URL of this exact view — what `hx-push-url` writes and
    /// what a saved view stores (§5.4).
    pub fn current_href(&self) -> String {
        self.href(&self.sort, &self.direction, self.page, self.per_page)
    }

    /// This view's filters, hung off a different path.
    ///
    /// Used to post the inventory's current selection to the planner, so what
    /// gets planned is exactly the set on screen rather than a filter
    /// reconstructed from a second source that could disagree with it.
    ///
    /// Sort and paging are carried too and simply ignored by the planner —
    /// harmless, and cheaper than a second href builder that would drift from
    /// this one.
    pub fn current_href_for(&self, base_path: &str) -> String {
        let full = self.href(&self.sort, &self.direction, self.page, self.per_page);
        match full.split_once('?') {
            Some((_, query)) => format!("{base_path}?{query}"),
            None => base_path.to_string(),
        }
    }

    /// The same view with every filter cleared, for the filtered-to-zero empty
    /// state's escape hatch.
    pub fn cleared_href(&self) -> String {
        let bare = TableNav {
            filter_pairs: Vec::new(),
            page: 1,
            ..self.clone()
        };
        bare.current_href()
    }

    /// Page numbers with `…` gaps: always first, last, current and its
    /// neighbours. Bounded output, so a 20k-device fleet does not render 200
    /// links a screen reader has to walk past.
    pub fn page_links(&self) -> Vec<PageLink> {
        let last = self.total_pages();
        let mut wanted: Vec<i64> = vec![1, last, self.page - 1, self.page, self.page + 1];
        wanted.retain(|n| *n >= 1 && *n <= last);
        wanted.sort_unstable();
        wanted.dedup();

        let mut out = Vec::with_capacity(wanted.len() + 2);
        let mut previous: Option<i64> = None;
        for n in wanted {
            if let Some(prev) = previous {
                if n > prev + 1 {
                    out.push(PageLink {
                        number: 0,
                        href: String::new(),
                        is_current: false,
                        is_gap: true,
                    });
                }
            }
            out.push(PageLink {
                number: n,
                href: self.href(&self.sort, &self.direction, n, self.per_page),
                is_current: n == self.page,
                is_gap: false,
            });
            previous = Some(n);
        }
        out
    }

    /// The page-size switcher (§5.5: 50 / 100 / 250, never infinite scroll).
    /// Changing page size returns to page 1 — page 7 at 50/page is not page 7
    /// at 250/page, and silently landing somewhere else is disorienting.
    pub fn page_size_options(&self) -> Vec<PageSizeOption> {
        PAGE_SIZES
            .iter()
            .map(|size| PageSizeOption {
                size: *size,
                href: self.href(&self.sort, &self.direction, 1, *size),
                is_current: *size == self.per_page,
            })
            .collect()
    }

    /// 1-based index of the first row on this page, or 0 when empty.
    pub fn range_start(&self) -> i64 {
        if self.total == 0 {
            0
        } else {
            (self.displayed_page() - 1) * self.per_page + 1
        }
    }

    /// 1-based index of the last row on this page.
    pub fn range_end(&self) -> i64 {
        (self.displayed_page() * self.per_page).min(self.total)
    }

    /// The page these ranges describe, held inside the table's real bounds.
    ///
    /// Handlers clamp before they query, so `page` is normally already in
    /// range. This is the floor under that: without it the struct will happily
    /// report `51–1 of 1` for page 2 of a single result — a reversed range that
    /// reads as data loss — and the guarantee would live in every caller rather
    /// than in the type that does the describing.
    fn displayed_page(&self) -> i64 {
        self.page.clamp(1, self.total_pages())
    }

    /// `"1–100 of 3,412"`, or `"0 of 0"` when nothing matches. Thousands
    /// separators because a technician reads these as quantities, not tokens.
    pub fn range_summary(&self) -> String {
        if self.total == 0 {
            return "0 devices".to_string();
        }
        format!(
            "{}–{} of {}",
            thousands(self.range_start()),
            thousands(self.range_end()),
            thousands(self.total)
        )
    }

    /// The [`PageRequest`] this navigation state resolves to. The single place
    /// URL state becomes `LIMIT`/`OFFSET`, so a page can never drift from the
    /// window it links to.
    pub fn page_request(&self) -> PageRequest {
        PageRequest::from_page_number(self.page, self.per_page)
    }
}

/// Group an integer with thousands separators: `3412` -> `3,412`.
pub fn thousands(n: i64) -> String {
    let negative = n < 0;
    let digits = n.abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if negative {
        format!("-{out}")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nav() -> TableNav {
        TableNav {
            base_path: "/devices".into(),
            region_id: "devices-region".into(),
            filter_pairs: vec![
                ("status".into(), "repair".into()),
                ("school".into(), "org-002".into()),
                ("q".into(), String::new()),
            ],
            sort: "asset_tag".into(),
            direction: "asc".into(),
            page: 1,
            per_page: 100,
            total: 412,
        }
    }

    #[test]
    fn page_sizes_snap_onto_the_offered_set() {
        assert_eq!(clamp_page_size(None), DEFAULT_PAGE_SIZE);
        assert_eq!(clamp_page_size(Some(50)), 50);
        assert_eq!(clamp_page_size(Some(100)), 100);
        assert_eq!(clamp_page_size(Some(250)), 250);
        // Between the rungs, and outside them entirely.
        assert_eq!(clamp_page_size(Some(75)), 50);
        assert_eq!(clamp_page_size(Some(10_000)), 250);
        assert_eq!(clamp_page_size(Some(0)), 50);
        assert_eq!(clamp_page_size(Some(-5)), 50);
    }

    #[test]
    fn canonical_filter_is_order_independent_and_drops_empties() {
        let a = canonical_filter(&[
            ("status".into(), "repair".into()),
            ("school".into(), "hs".into()),
            ("q".into(), String::new()),
        ]);
        let b = canonical_filter(&[
            ("school".into(), "hs".into()),
            ("q".into(), String::new()),
            ("status".into(), "repair".into()),
        ]);
        assert_eq!(a, b, "the same filter must canonicalise identically");
        assert_eq!(a, "school=hs&status=repair");
        assert_eq!(filter_hash(&a), filter_hash(&b));
    }

    #[test]
    fn canonical_filter_percent_encodes_values() {
        let s = canonical_filter(&[("ou".into(), "/Students/Grade 5&6".into())]);
        assert!(!s.contains(' '), "a space would break the pair split: {s}");
        assert_eq!(s.matches('&').count(), 0, "the value's & must be encoded");
    }

    #[test]
    fn filter_hash_changes_when_the_filter_does() {
        let a = filter_hash(&canonical_filter(&[("status".into(), "repair".into())]));
        let b = filter_hash(&canonical_filter(&[("status".into(), "lost".into())]));
        assert_ne!(a, b);
        assert_eq!(a.len(), FILTER_HASH_LEN);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn an_empty_filter_hashes_stably() {
        assert_eq!(canonical_filter(&[]), "");
        assert_eq!(filter_hash(""), filter_hash(&canonical_filter(&[])));
    }

    #[test]
    fn unknown_selection_modes_fall_back_to_the_wider_scope() {
        assert_eq!(SelectionMode::parse("picked"), SelectionMode::Picked);
        assert_eq!(SelectionMode::parse("matching"), SelectionMode::Matching);
        // The dangerous direction: never silently narrow.
        assert_eq!(SelectionMode::parse(""), SelectionMode::Matching);
        assert_eq!(SelectionMode::parse("page"), SelectionMode::Matching);
        assert_eq!(SelectionMode::default(), SelectionMode::Matching);
    }

    /// The whole point of filter-scoped selection: the wire carries a filter,
    /// not a list of ids, so a 400-row scope is four fields rather than 400.
    #[test]
    fn selection_carries_a_filter_hash_not_ids() {
        let sel = Selection::new(
            SelectionMode::Matching,
            &[
                ("status".into(), "repair".into()),
                ("school".into(), "org-002".into()),
            ],
            400,
            100,
        );
        assert_eq!(sel.filter, "school=org-002&status=repair");
        assert_eq!(sel.filter_hash, filter_hash(&sel.filter));
        assert_eq!(sel.match_count, 400);
        assert!(sel.spans_more_than_a_page());
        assert!(sel.is_filtered());
    }

    #[test]
    fn selection_within_one_page_does_not_claim_to_span_pages() {
        let sel = Selection::new(SelectionMode::Matching, &[], 42, 100);
        assert!(!sel.spans_more_than_a_page());
        assert!(!sel.is_filtered());
    }

    #[test]
    fn sort_links_flip_only_the_sorted_column_and_reset_to_page_one() {
        let mut n = nav();
        n.page = 7;

        // The sorted column toggles asc -> desc.
        let flipped = n.sort_href("asset_tag");
        assert!(flipped.contains("sort=asset_tag"), "{flipped}");
        assert!(flipped.contains("dir=desc"), "{flipped}");
        assert!(!flipped.contains("page="), "re-sorting must reset paging");

        // Another column starts ascending.
        let other = n.sort_href("aue_date");
        assert!(other.contains("sort=aue_date&dir=asc"), "{other}");

        // Filters survive the sort — this is what makes a view bookmarkable.
        assert!(flipped.contains("status=repair"), "{flipped}");
        assert!(flipped.contains("school=org-002"), "{flipped}");
        assert!(!flipped.contains("q="), "empty filters stay out of the URL");
    }

    #[test]
    fn aria_sort_marks_exactly_the_sorted_column() {
        let mut n = nav();
        assert_eq!(n.aria_sort("asset_tag"), "ascending");
        assert_eq!(n.aria_sort("serial_number"), "none");
        assert_eq!(n.sort_indicator("asset_tag"), "▴");
        assert_eq!(n.sort_indicator("serial_number"), "");

        n.direction = "desc".into();
        assert_eq!(n.aria_sort("asset_tag"), "descending");
        assert_eq!(n.sort_indicator("asset_tag"), "▾");
    }

    #[test]
    fn paging_maths_matches_the_summary_and_the_sql_window() {
        let mut n = nav();
        assert_eq!(n.total_pages(), 5); // 412 / 100
        assert_eq!(n.range_start(), 1);
        assert_eq!(n.range_end(), 100);
        assert_eq!(n.range_summary(), "1–100 of 412");
        assert!(n.is_first_page());
        assert!(!n.is_last_page());
        assert_eq!(n.page_request().limit(), 100);
        assert_eq!(n.page_request().offset(), 0);

        n.page = 5;
        assert_eq!(n.range_start(), 401);
        assert_eq!(n.range_end(), 412, "the last page is short");
        assert!(n.is_last_page());
        assert_eq!(n.page_request().offset(), 400);
    }

    #[test]
    fn an_empty_result_still_has_one_page_and_says_so() {
        let mut n = nav();
        n.total = 0;
        assert_eq!(n.total_pages(), 1);
        assert_eq!(n.range_start(), 0);
        assert_eq!(n.range_summary(), "0 devices");
        assert!(n.is_first_page());
        assert!(n.is_last_page());
    }

    #[test]
    fn page_links_elide_and_always_include_first_current_and_last() {
        let mut n = nav();
        n.total = 10_000; // 100 pages
        n.page = 50;
        let links = n.page_links();
        let numbers: Vec<i64> = links
            .iter()
            .filter(|l| !l.is_gap)
            .map(|l| l.number)
            .collect();
        assert_eq!(numbers, vec![1, 49, 50, 51, 100]);
        assert_eq!(links.iter().filter(|l| l.is_gap).count(), 2);
        assert_eq!(links.iter().filter(|l| l.is_current).count(), 1);
        assert!(links.iter().all(|l| l.is_gap || !l.href.is_empty()));
    }

    #[test]
    fn page_links_do_not_gap_when_pages_are_contiguous() {
        let mut n = nav();
        n.total = 300; // 3 pages
        n.page = 2;
        let links = n.page_links();
        assert!(links.iter().all(|l| !l.is_gap));
        assert_eq!(
            links.iter().map(|l| l.number).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn page_one_is_the_bare_url_so_shared_links_match() {
        let n = nav();
        let first = n.page_links()[0].href.clone();
        assert!(!first.contains("page="), "{first}");
        assert_eq!(first, n.current_href());
    }

    #[test]
    fn default_page_size_stays_out_of_the_url() {
        let n = nav();
        assert!(!n.current_href().contains("per_page="));
        let options = n.page_size_options();
        assert_eq!(options.len(), 3);
        assert!(options.iter().filter(|o| o.is_current).count() == 1);
        let two_fifty = options.iter().find(|o| o.size == 250).unwrap();
        assert!(
            two_fifty.href.contains("per_page=250"),
            "{}",
            two_fifty.href
        );
        assert!(
            !two_fifty.href.contains("&page="),
            "changing page size returns to page 1: {}",
            two_fifty.href
        );
    }

    #[test]
    fn clearing_filters_keeps_the_sort_and_drops_everything_else() {
        let mut n = nav();
        n.page = 4;
        let cleared = n.cleared_href();
        assert_eq!(cleared, "/devices?sort=asset_tag&dir=asc");
        assert!(!cleared.contains("status="));
        assert!(!cleared.contains("page="));
    }

    #[test]
    fn prev_and_next_stay_inside_the_result_set() {
        let mut n = nav();
        assert_eq!(n.prev_href(), n.current_href(), "prev on page 1 is page 1");
        n.page = 5;
        assert_eq!(n.next_href(), n.current_href(), "next on the last page");
    }

    #[test]
    fn thousands_groups_from_the_right() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(7), "7");
        assert_eq!(thousands(100), "100");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(20_412), "20,412");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(thousands(-1_234), "-1,234");
    }

    /// The range a page reports can never run backwards or past the total.
    ///
    /// This lives here, on the struct that computes it, rather than being
    /// inferred from rendered HTML. The console test that used to cover it
    /// searched the whole document for the substring `"801"` — and the page
    /// also carries a random 64-hex CSRF token, which contains that substring
    /// about 1.5% of the time. It was a 1-in-66 coin flip that passed locally
    /// for months and then failed on CI.
    ///
    /// Sweeping the combinations costs microseconds and cannot flake.
    #[test]
    fn a_reported_range_never_runs_backwards_or_past_the_total() {
        for total in [0, 1, 19, 20, 21, 100, 3_412] {
            for per_page in [50, 100, 250] {
                for page in 1..=12 {
                    let nav = TableNav {
                        base_path: "/devices".into(),
                        region_id: "r".into(),
                        filter_pairs: vec![],
                        sort: "asset_tag".into(),
                        direction: "asc".into(),
                        page,
                        per_page,
                        total,
                    };
                    let (start, end) = (nav.range_start(), nav.range_end());
                    let where_ = format!("page {page}, per_page {per_page}, total {total}");

                    if total == 0 {
                        assert_eq!(nav.range_summary(), "0 devices", "{where_}");
                        continue;
                    }
                    // An out-of-range page is the case that produced
                    // "801-20 of 20": start ran past end, and the summary read
                    // as a reversed range to anyone looking at it.
                    assert!(start >= 1, "start {start} below 1 at {where_}");
                    assert!(end <= total, "end {end} past total {total} at {where_}");
                    assert!(start <= end, "reversed range {start}-{end} at {where_}");
                }
            }
        }
    }
}
