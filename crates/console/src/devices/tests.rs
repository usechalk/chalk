//! Tests for the device inventory.
//!
//! Three properties get the most attention, because each is a way this page
//! could be wrong while looking right:
//!
//! * the page window reaches the **repository**, not a `Vec::truncate` after
//!   the fact (`users_list` is the counter-example this module exists not to
//!   copy);
//! * sort and filter survive a **round trip through the URL**, which is what
//!   makes a filtered view bookmarkable and a saved view possible;
//! * the bulk form carries a **filter**, never a list of ids, and always says
//!   which selection scope is in effect.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::db::repository::{AssetRepository, ChalkRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::error::Result;
use chalk_core::models::asset::{Asset, AssetPatch, AssetStatus, MatchState, NewAssetEvent};
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::page::{Page, PageRequest};
use chalk_core::models::user::User;
use chrono::{NaiveDate, TimeZone, Utc};
use tower::ServiceExt;

use super::*;
use crate::{router, AppState};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Records every window and filter the console asks the repository for, then
/// delegates. This is how "pagination is real" is asserted from the outside:
/// if the handler ever fetched everything and narrowed in Rust, the recorded
/// limit would be the fleet size rather than the page size.
struct SpyAssets {
    inner: Arc<dyn AssetRepository>,
    calls: Mutex<Vec<(AssetFilter, i64, i64)>>,
}

impl SpyAssets {
    fn new(inner: Arc<dyn AssetRepository>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            calls: Mutex::new(Vec::new()),
        })
    }

    /// (filter, limit, offset) of every paged listing, in call order.
    fn listings(&self) -> Vec<(AssetFilter, i64, i64)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl AssetRepository for SpyAssets {
    async fn create_asset(&self, asset: &Asset) -> Result<()> {
        self.inner.create_asset(asset).await
    }
    async fn upsert_asset(&self, asset: &Asset) -> Result<()> {
        self.inner.upsert_asset(asset).await
    }
    async fn get_asset(&self, id: &str) -> Result<Option<Asset>> {
        self.inner.get_asset(id).await
    }
    async fn get_asset_by_google_device_id(&self, id: &str) -> Result<Option<Asset>> {
        self.inner.get_asset_by_google_device_id(id).await
    }
    async fn get_asset_by_serial(&self, serial: &str) -> Result<Option<Asset>> {
        self.inner.get_asset_by_serial(serial).await
    }
    async fn find_assets_by_asset_tag(&self, asset_tag: &str) -> Result<Vec<Asset>> {
        self.inner.find_assets_by_asset_tag(asset_tag).await
    }
    async fn list_assets(&self, filter: &AssetFilter, page: PageRequest) -> Result<Page<Asset>> {
        self.inner.list_assets(filter, page).await
    }
    async fn list_assets_with_roster(
        &self,
        filter: &AssetFilter,
        page: PageRequest,
    ) -> Result<Page<AssetRow>> {
        self.calls
            .lock()
            .unwrap()
            .push((filter.clone(), page.limit(), page.offset()));
        self.inner.list_assets_with_roster(filter, page).await
    }
    async fn count_assets(&self, filter: &AssetFilter) -> Result<i64> {
        self.inner.count_assets(filter).await
    }
    async fn update_asset(&self, id: &str, patch: &AssetPatch) -> Result<bool> {
        self.inner.update_asset(id, patch).await
    }
    async fn apply_patch_with_event(
        &self,
        id: &str,
        patch: &AssetPatch,
        event: &NewAssetEvent,
    ) -> Result<bool> {
        self.inner.apply_patch_with_event(id, patch, event).await
    }
}

struct Fixture {
    state: Arc<AppState>,
    spy: Arc<SpyAssets>,
}

async fn fixture() -> Fixture {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        DatabasePool::Postgres(_) => unreachable!("test setup uses sqlite memory"),
    };
    let repo = Arc::new(repo);
    let spy = SpyAssets::new(repo.clone() as Arc<dyn AssetRepository>);

    let mut config = chalk_core::config::ChalkConfig::generate_default();
    config.sis.provider = Some(chalk_core::config::SisProvider::PowerSchool);

    let repo2: Arc<dyn chalk_core::db::repository::AssetEventRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo;
    let state = Arc::new(
        AppState::new(chalk_repo, config)
            .with_assets(spy.clone() as Arc<dyn AssetRepository>, repo2),
    );
    Fixture { state, spy }
}

fn org(sourced_id: &str, name: &str, org_type: OrgType) -> Org {
    Org {
        sourced_id: sourced_id.to_string(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        name: name.to_string(),
        org_type,
        identifier: None,
        parent: None,
        children: vec![],
    }
}

fn user(sourced_id: &str, given: &str, family: &str) -> User {
    User {
        sourced_id: sourced_id.to_string(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        username: format!("{given}.{family}").to_lowercase(),
        user_ids: vec![],
        enabled_user: true,
        given_name: given.to_string(),
        family_name: family.to_string(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some(format!("{given}.{family}@example.edu").to_lowercase()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    }
}

/// `count` devices, every fourth one unassigned, alternating status, with AUE
/// dates spread either side of the urgency threshold.
async fn seed(state: &AppState, count: usize) {
    let repo = &state.repo;
    repo.upsert_org(&org("org-hs", "Springfield High", OrgType::School))
        .await
        .unwrap();
    repo.upsert_org(&org("org-ms", "Shelbyville Middle", OrgType::School))
        .await
        .unwrap();
    repo.upsert_org(&org("org-dist", "Springfield District", OrgType::District))
        .await
        .unwrap();
    repo.upsert_user(&user("stu-1", "Lisa", "Simpson"))
        .await
        .unwrap();
    repo.upsert_user(&user("stu-2", "Bart", "Simpson"))
        .await
        .unwrap();

    let assets = state.assets.clone().unwrap();
    for i in 1..=count {
        let mut a = Asset::new(format!("dev-{i:04}"));
        a.asset_tag = Some(format!("CB-{i:05}"));
        a.serial_number = Some(format!("SN{i:06}"));
        a.model = Some(if i % 2 == 0 {
            "Spin 511".into()
        } else {
            "C733".into()
        });
        a.status = match i % 5 {
            0 => AssetStatus::Repair,
            1 => AssetStatus::Active,
            2 => AssetStatus::Storage,
            3 => AssetStatus::Retired,
            _ => AssetStatus::Lost,
        };
        a.school_org_sourced_id = Some(if i % 2 == 0 {
            "org-hs".into()
        } else {
            "org-ms".into()
        });
        a.assigned_user_sourced_id = if i % 4 == 0 {
            None
        } else if i % 2 == 0 {
            Some("stu-1".into())
        } else {
            Some("stu-2".into())
        };
        a.match_state = if a.assigned_user_sourced_id.is_some() {
            MatchState::Matched
        } else {
            MatchState::Unmatched
        };
        a.org_unit_path = Some(if i % 3 == 0 {
            "/Students/HS".to_string()
        } else {
            "/Students/MS".to_string()
        });
        a.aue_date = Some(NaiveDate::from_ymd_opt(2026 + (i % 5) as i32, 6, 30).unwrap());
        a.last_sync_at = Some(Utc.with_ymd_and_hms(2026, 7, 20, 4, 12, 0).unwrap());
        assets.create_asset(&a).await.unwrap();
    }
}

async fn body_of(response: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    let response = router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    (response.status(), body_of(response).await)
}

/// A response body with no HTML assumptions, for the CSV export.
async fn get_raw(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    let response = router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// An HTMX-issued request, which must get the region rather than the document.
async fn get_htmx(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("HX-Request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (response.status(), body_of(response).await)
}

// ---------------------------------------------------------------------------
// Query parsing: the URL is the state
// ---------------------------------------------------------------------------

fn query(uri: &str) -> DevicesQuery {
    let qs = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    serde_urlencoded::from_str(qs).expect("query must parse")
}

#[test]
fn every_filter_maps_onto_a_repository_filter_field() {
    let q = query(
        "/devices?status=repair&school=org-hs&assigned=unassigned&ou=/Students\
         &aue_before=2027-06-30&q=CB-1&sort=aue_date&dir=desc&page=3&per_page=250",
    );
    let f = q.to_asset_filter();

    assert_eq!(f.status, Some(AssetStatus::Repair));
    assert_eq!(f.school_org_sourced_id.as_deref(), Some("org-hs"));
    assert_eq!(f.assigned, Some(false));
    assert_eq!(f.org_unit_path_prefix.as_deref(), Some("/Students"));
    assert_eq!(f.aue_before, NaiveDate::from_ymd_opt(2027, 6, 30));
    assert_eq!(f.search.as_deref(), Some("CB-1"));
    assert_eq!(f.sort, AssetSort::AueDate);
    assert_eq!(f.direction, SortDirection::Desc);

    // Paging is separate from filtering, and lands on a real window.
    let nav = q.to_nav(1_000);
    assert_eq!(nav.per_page, 250);
    assert_eq!(nav.page_request().limit(), 250);
    assert_eq!(nav.page_request().offset(), 500);
}

#[test]
fn assigned_is_tri_state() {
    assert_eq!(
        query("/devices?assigned=assigned")
            .to_asset_filter()
            .assigned,
        Some(true)
    );
    assert_eq!(
        query("/devices?assigned=unassigned")
            .to_asset_filter()
            .assigned,
        Some(false)
    );
    assert_eq!(query("/devices").to_asset_filter().assigned, None);
    // A value from a hand-edited URL widens rather than erroring.
    assert_eq!(
        query("/devices?assigned=maybe").to_asset_filter().assigned,
        None
    );
}

#[test]
fn nonsense_url_values_degrade_to_the_default_view() {
    let q =
        query("/devices?status=exploded&sort=DROP+TABLE&dir=sideways&aue_before=soon&per_page=7");
    let f = q.to_asset_filter();
    assert_eq!(f.status, None, "an unknown status must not become a filter");
    assert_eq!(f.sort, AssetSort::AssetTag, "the sort is a closed enum");
    assert_eq!(f.direction, SortDirection::Asc);
    assert_eq!(f.aue_before, None);
    assert_eq!(q.per_page(), 50, "an off-ladder page size snaps down");
    assert!(!q.is_filtered(), "none of that narrowed anything");
}

#[test]
fn sort_and_paging_are_not_part_of_the_selection_scope() {
    // Re-sorting or paging must not change what a bulk action would touch.
    let a = query("/devices?status=repair&sort=aue_date&dir=desc&page=4");
    let b = query("/devices?status=repair&sort=asset_tag&dir=asc");
    assert_eq!(a.filter_pairs(), b.filter_pairs());
    assert_eq!(
        crate::table::canonical_filter(&a.filter_pairs()),
        crate::table::canonical_filter(&b.filter_pairs())
    );
}

#[test]
fn filters_round_trip_through_the_generated_urls() {
    let q = query("/devices?status=repair&school=org-hs&q=CB");
    let nav = q.to_nav(412);

    // Sorting a filtered view keeps the filter — this is what makes the URL a
    // saved view rather than a one-shot.
    let sorted = nav.sort_href("aue_date");
    let reparsed = query(&sorted);
    assert_eq!(reparsed.filter_pairs(), q.filter_pairs());
    assert_eq!(reparsed.sort_column(), AssetSort::AueDate);

    // And so does paging.
    let page3 = nav.page_links().last().unwrap().href.clone();
    let reparsed = query(&page3);
    assert_eq!(reparsed.filter_pairs(), q.filter_pairs());
    assert_eq!(reparsed.page_number(), nav.total_pages());
}

// ---------------------------------------------------------------------------
// AUE urgency
// ---------------------------------------------------------------------------

#[test]
fn aue_urgency_is_two_tone_around_a_stated_threshold() {
    let today = NaiveDate::from_ymd_opt(2026, 7, 25).unwrap();
    let of = |y, m, d| AueUrgency::of(NaiveDate::from_ymd_opt(y, m, d), today);

    assert_eq!(of(2026, 7, 24), AueUrgency::Past);
    assert_eq!(of(2026, 7, 25), AueUrgency::Soon, "today is not yet past");
    assert_eq!(
        of(2027, 7, 24),
        AueUrgency::Soon,
        "one day inside 12 months"
    );
    assert_eq!(of(2027, 7, 25), AueUrgency::Later, "exactly 12 months out");
    assert_eq!(of(2031, 1, 1), AueUrgency::Later);
    assert_eq!(AueUrgency::of(None, today), AueUrgency::Unknown);
}

/// §8 and §4's design law: urgency is never carried by colour alone, and the
/// threshold is stated rather than assumed.
#[test]
fn aue_urgency_states_its_threshold_in_words() {
    assert_eq!(AueUrgency::Past.note(), "past expiry");
    assert_eq!(AueUrgency::Soon.note(), "within 12 months");
    assert!(AueUrgency::Later.note().is_empty());
    assert!(AueUrgency::Unknown.note().is_empty());
    assert!(AueUrgency::Soon
        .note()
        .contains(&AUE_SOON_MONTHS.to_string()));
}

#[test]
fn aue_threshold_survives_month_length_differences() {
    // 31 Aug + 12 months is a real date; 31 Jan + 1 month is not.
    let today = NaiveDate::from_ymd_opt(2026, 8, 31).unwrap();
    assert_eq!(
        AueUrgency::of(NaiveDate::from_ymd_opt(2027, 8, 30), today),
        AueUrgency::Soon
    );
    let leap_edge = NaiveDate::from_ymd_opt(2028, 2, 29).unwrap();
    assert_eq!(
        AueUrgency::of(NaiveDate::from_ymd_opt(2029, 3, 1), leap_edge),
        AueUrgency::Later
    );
}

#[test]
fn every_device_status_has_a_distinct_badge_and_a_text_label() {
    let all = [
        AssetStatus::Active,
        AssetStatus::Repair,
        AssetStatus::Storage,
        AssetStatus::Retired,
        AssetStatus::Deprovisioned,
        AssetStatus::Lost,
    ];
    let mut classes: Vec<&str> = all.iter().map(|s| status_badge_class(*s)).collect();
    let labels: Vec<&str> = all.iter().map(|s| status_label(*s)).collect();
    classes.sort_unstable();
    classes.dedup();
    assert_eq!(classes.len(), all.len(), "two statuses share a badge hue");
    assert!(
        labels.iter().all(|l| !l.is_empty()),
        "colour is never alone"
    );
}

// ---------------------------------------------------------------------------
// Pagination reaches SQL
// ---------------------------------------------------------------------------

/// The property this whole module exists for: the console asks the repository
/// for **one page**, filtered, and never for the fleet.
#[tokio::test]
async fn pagination_and_filters_reach_the_repository_not_a_rust_filter() {
    let f = fixture().await;
    // 300, not 120. `seed` makes every fifth device Repair, so 120 would yield
    // 24 matches and page 2 of 50 would be *past the end* — a real scenario,
    // but the clamp's scenario, which costs a second query by design. Asserting
    // "exactly one query" through it would assert the absence of the clamp
    // rather than the presence of SQL paging. 300 gives 60 matches, so page 2
    // sits inside the result set and this stays a clean test of the property it
    // is named for. (Page size cannot be lowered instead: `clamp_page_size`
    // snaps to the offered 50/100/250.)
    seed(&f.state, 300).await;

    let (status, _) = get(
        f.state.clone(),
        "/devices?status=repair&per_page=50&page=2&sort=serial_number&dir=desc",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let listings = f.spy.listings();
    assert_eq!(listings.len(), 1, "one windowed query per page render");
    let (filter, limit, offset) = &listings[0];
    assert_eq!(*limit, 50, "the page size reached the repository");
    assert_eq!(*offset, 50, "page 2 of 50 is offset 50");
    assert_eq!(filter.status, Some(AssetStatus::Repair));
    assert_eq!(filter.sort, AssetSort::SerialNumber);
    assert_eq!(filter.direction, SortDirection::Desc);
}

/// A larger fleet must not make the request bigger. If the handler ever grew a
/// "fetch everything then narrow" path, the recorded limit would track the
/// seed size instead of the page size.
#[tokio::test]
async fn the_window_does_not_grow_with_the_fleet() {
    for fleet in [10usize, 300] {
        let f = fixture().await;
        seed(&f.state, fleet).await;
        let (status, _) = get(f.state.clone(), "/devices").await;
        assert_eq!(status, StatusCode::OK);
        let (_, limit, offset) = f.spy.listings()[0].clone();
        assert_eq!(limit, 100, "fleet of {fleet} asked for {limit} rows");
        assert_eq!(offset, 0);
    }
}

#[tokio::test]
async fn a_page_renders_exactly_its_window() {
    let f = fixture().await;
    seed(&f.state, 120).await;

    let (_, html) = get(f.state.clone(), "/devices?per_page=50").await;
    assert_eq!(html.matches("data-row-check").count(), 50);
    assert!(
        html.contains("1–50 of 120"),
        "summary must reflect the window"
    );

    let (_, html) = get(f.state.clone(), "/devices?per_page=50&page=3").await;
    assert_eq!(
        html.matches("data-row-check").count(),
        20,
        "short last page"
    );
    assert!(html.contains("101–120 of 120"));
}

#[tokio::test]
async fn page_size_options_are_the_offered_ladder_and_never_infinite() {
    let f = fixture().await;
    seed(&f.state, 300).await;
    let (_, html) = get(f.state.clone(), "/devices").await;
    for size in crate::table::PAGE_SIZES {
        assert!(
            html.contains(&format!(">{size}</")),
            "page size {size} is not offered"
        );
    }
    assert!(html.contains("pagination"), "pagination must be present");
}

// ---------------------------------------------------------------------------
// The student and school columns — the product argument
// ---------------------------------------------------------------------------

#[tokio::test]
async fn student_and_school_render_beside_the_device() {
    let f = fixture().await;
    seed(&f.state, 8).await;
    let (status, html) = get(f.state.clone(), "/devices").await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        html.contains("Simpson, Lisa"),
        "assigned student is missing"
    );
    assert!(html.contains("Simpson, Bart"));
    assert!(html.contains("Springfield High"), "school is missing");
    assert!(html.contains("Shelbyville Middle"));
    // The student cell links to the roster record — the join is navigable, not
    // just printed.
    assert!(html.contains(r#"href="/users/stu-1""#));
    // And the device identifiers are there to hang it on.
    assert!(html.contains("CB-00001"));
    assert!(html.contains("SN000001"));
}

#[tokio::test]
async fn unassigned_devices_render_a_placeholder_not_a_broken_link() {
    let f = fixture().await;
    seed(&f.state, 8).await; // every 4th device is unassigned
    let (_, html) = get(f.state.clone(), "/devices?assigned=unassigned").await;
    assert!(html.contains("cell-empty"), "no placeholder cell rendered");
    assert!(
        !html.contains(r#"href="/users/""#),
        "an empty user link shipped"
    );
}

#[tokio::test]
async fn the_matched_headline_is_counted_against_the_same_filter() {
    let f = fixture().await;
    seed(&f.state, 8).await; // 2 of 8 unassigned
    let (_, html) = get(f.state.clone(), "/devices").await;
    assert!(
        html.contains("6 of 8 attached to a student"),
        "matched headline missing or wrong"
    );
}

// ---------------------------------------------------------------------------
// Filter-scoped selection
// ---------------------------------------------------------------------------

/// The core safety property. A 400-row scope must travel as a filter and a
/// digest, not as 400 hidden inputs — and the bar must say the scope out loud.
#[tokio::test]
async fn selection_carries_a_filter_hash_rather_than_ids() {
    let f = fixture().await;
    seed(&f.state, 400).await;

    // Every device is at /Students/*, so this filter matches all 400 while the
    // page shows 100.
    let (_, html) = get(f.state.clone(), "/devices?ou=/Students").await;

    let expected_filter = crate::table::canonical_filter(&[("ou".into(), "/Students".into())]);
    let expected_hash = crate::table::filter_hash(&expected_filter);

    assert!(
        html.contains(&format!(r#"name="filter_hash" value="{expected_hash}""#)),
        "the bulk form does not carry the filter digest"
    );
    assert!(
        html.contains(r#"name="match_count" value="400""#),
        "the bulk form does not carry the displayed match count"
    );
    assert!(
        html.contains(r#"name="selection_mode" value="matching""#),
        "the resting scope must be the filter, not the page"
    );

    // The count names the filter scope, never the page.
    assert!(html.contains("400 devices match this filter"), "{html:.0}");
    assert!(
        html.contains("including 300 devices on other pages"),
        "the page/filter gap must be spelled out"
    );
    assert!(
        !html.contains("100 selected"),
        "the bar must never present a page count as the selection"
    );

    // 400 ids in the body is exactly what this design refuses.
    assert_eq!(
        html.matches(r#"name="ids""#).count(),
        100,
        "only the visible page carries per-row checkboxes"
    );
}

#[tokio::test]
async fn an_unfiltered_bar_says_so_rather_than_naming_a_filter() {
    let f = fixture().await;
    seed(&f.state, 30).await;
    let (_, html) = get(f.state.clone(), "/devices").await;
    assert!(html.contains("All 30 devices in the inventory"));
    assert!(!html.contains("match this filter"));
    assert!(
        !html.contains("on other pages"),
        "nothing is beyond the page here"
    );
}

/// The bulk bar posts to the **planner**, never to a writer.
///
/// This test used to assert the opposite — that the bar offered no action at
/// all, because acting on "everything matching this filter" is only safe once
/// something stands between the filter and the write. C4 is that something, so
/// the constraint has been met rather than dropped, and what it now pins is
/// that the buttons produce a preview instead of a change.
#[tokio::test]
async fn the_bulk_bar_posts_to_the_planner_not_to_a_writer() {
    let f = fixture().await;
    seed(&f.state, 10).await;
    let (_, html) = get(f.state.clone(), "/devices").await;

    assert!(
        html.contains(r#"action="/devices/changes"#),
        "the bulk form must post to the planner"
    );
    assert!(html.contains("Nothing is applied yet"));
    assert!(
        !html.contains(r#"action="/devices/bulk""#),
        "there must be no path that writes without a preview"
    );
    // The actions offered are the ones the planner can actually plan. An
    // action with no planner rule would produce a preview that cannot commit.
    for action in ["unassign", "shared", "status"] {
        assert!(
            html.contains(&format!(r#"value="{action}""#)),
            "missing bulk action {action}"
        );
    }
    assert!(
        !html.contains("Move to OU"),
        "an OU move is a Google write, which cannot be planned yet"
    );
}

/// The planner is posted the operator's *current* filter, so what gets planned
/// is exactly the set on screen rather than one reconstructed from a second
/// source that could disagree with it.
#[tokio::test]
async fn the_bulk_form_carries_the_active_filter() {
    let f = fixture().await;
    seed(&f.state, 30).await;

    let (_, filtered) = get(f.state.clone(), "/devices?status=repair").await;
    assert!(
        filtered.contains("/devices/changes?status=repair"),
        "the filter must travel with the plan request"
    );

    let (_, unfiltered) = get(f.state.clone(), "/devices").await;
    assert!(unfiltered.contains(r#"action="/devices/changes"#));
    assert!(
        !unfiltered.contains("status=repair"),
        "an unfiltered view must not smuggle a filter into the plan"
    );
}

/// The export carries the operator's filter, because "export everything" is
/// rarely the question — "give me the 400 Chromebooks at the middle school" is.
#[tokio::test]
async fn the_export_respects_the_active_filter() {
    let f = fixture().await;
    seed(&f.state, 40).await;

    let (status, all) = get_raw(f.state.clone(), "/devices/export.csv").await;
    assert_eq!(status, StatusCode::OK);
    let all_rows = all.lines().count() - 1;
    assert_eq!(all_rows, 40, "every device, one row each");

    let (_, filtered) = get_raw(f.state.clone(), "/devices/export.csv?status=repair").await;
    let filtered_rows = filtered.lines().count() - 1;
    assert!(
        filtered_rows > 0 && filtered_rows < all_rows,
        "the filter must narrow the export: {filtered_rows} of {all_rows}"
    );
}

/// It downloads rather than rendering, and carries the header the importer
/// reads — so a round trip through a spreadsheet is lossless.
#[tokio::test]
async fn the_export_is_a_csv_download_with_the_importable_header() {
    let f = fixture().await;
    seed(&f.state, 3).await;

    let response = router(f.state.clone())
        .oneshot(
            Request::builder()
                .uri("/devices/export.csv")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let disposition = response
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(content_type.starts_with("text/csv"));
    assert!(disposition.contains("attachment"), "it must download");
    assert!(disposition.contains("chalk-devices.csv"));

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();
    let header = body.lines().next().unwrap();
    for col in chalk_core::asset_csv::IMPORTABLE_COLUMNS {
        assert!(header.contains(col), "export is missing {col}");
    }
}

/// The digest is stable for a given filter and changes when the filter does —
/// which is the whole basis for detecting a scope that moved under the
/// operator.
#[tokio::test]
async fn the_filter_digest_tracks_the_filter() {
    let f = fixture().await;
    seed(&f.state, 20).await;

    let extract = |html: &str| {
        let marker = r#"name="filter_hash" value=""#;
        let start = html.find(marker).expect("no digest") + marker.len();
        html[start..].split('"').next().unwrap().to_string()
    };

    let (_, a) = get(f.state.clone(), "/devices?status=repair&school=org-hs").await;
    let (_, b) = get(f.state.clone(), "/devices?school=org-hs&status=repair").await;
    let (_, c) = get(f.state.clone(), "/devices?status=lost&school=org-hs").await;

    assert_eq!(
        extract(&a),
        extract(&b),
        "parameter order must not change the scope"
    );
    assert_ne!(
        extract(&a),
        extract(&c),
        "a different filter is a different scope"
    );
}

// ---------------------------------------------------------------------------
// Empty states
// ---------------------------------------------------------------------------

#[tokio::test]
async fn first_run_offers_the_connect_call_to_action() {
    let f = fixture().await;
    let (status, html) = get(f.state.clone(), "/devices").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("No devices yet."));
    assert!(html.contains("Connect Google Workspace"));
    assert!(!html.contains("No devices match these filters"));
}

/// §5.14's hard rule: never show first-run while a filter is active, because a
/// technician reads it as the fleet having disappeared.
#[tokio::test]
async fn a_filter_that_matches_nothing_is_not_the_first_run_state() {
    let f = fixture().await;
    seed(&f.state, 20).await;

    let (status, html) = get(f.state.clone(), "/devices?q=nothing-matches-this").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("No devices match these filters."));
    assert!(
        !html.contains("No devices yet."),
        "first-run shown while filtered — reads as data loss"
    );
    assert!(
        !html.contains("Connect Google Workspace"),
        "the connect CTA must not appear once devices exist"
    );
    assert!(
        html.contains("Clear filters"),
        "no escape from the empty filter"
    );
}

#[tokio::test]
async fn the_inventory_opts_out_of_the_reading_width_cap() {
    let f = fixture().await;
    seed(&f.state, 5).await;

    // .content caps at 1200px, which suits settings and forms. Ten columns
    // inside that, minus a 260px sidebar, leaves ~105px each and forces a
    // horizontal scrollbar on the one screen a technician lives in all day.
    // DESIGN_SYSTEM §3.5: "console content max-width none (tables want the
    // room)". Losing this modifier silently reintroduces the scrollbar, which
    // no other test would notice.
    let (status, html) = get(f.state.clone(), "/devices").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("content--wide"),
        "the inventory must opt out of the reading-width cap"
    );
}

#[tokio::test]
async fn a_page_past_the_end_clamps_instead_of_claiming_the_fleet_is_gone() {
    let f = fixture().await;
    seed(&f.state, 20).await;

    // Page 9 of a 20-device result set. An out-of-range page comes back empty
    // but with a non-zero total, so it matches neither `has_rows` nor
    // `is_filtered_empty` and used to fall through to the first-run state —
    // telling an operator with a populated fleet to go connect Google. It also
    // rendered a reversed range ("801-20 of 20").
    //
    // Reachable without typing a URL: bookmark a filtered page, let the
    // devices get resolved, come back.
    let (status, html) = get(f.state.clone(), "/devices?page=9").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !html.contains("No devices yet."),
        "first-run shown on an out-of-range page — reads as data loss"
    );
    assert!(
        !html.contains("Connect Google Workspace"),
        "the connect CTA must not appear once devices exist"
    );
    assert!(
        html.contains("name=\"ids\""),
        "clamping should land on the last page of results, with rows"
    );
    assert!(
        !html.contains("801"),
        "reversed or out-of-range summary still rendered"
    );
}

#[tokio::test]
async fn a_page_past_the_end_of_a_filter_clamps_within_that_filter() {
    let f = fixture().await;
    seed(&f.state, 20).await;

    // Same overrun, but narrowed. The clamp must stay inside the filter rather
    // than dumping the operator back into the full inventory.
    //
    // Note the value is `unassigned`, not `false`. An unrecognised value
    // degrades to "no filter" by design, so writing `assigned=false` here would
    // silently test the unfiltered path and pass for the wrong reason — which
    // is exactly what an earlier draft of this test did.
    let (status, html) = get(f.state.clone(), "/devices?assigned=unassigned&page=9").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains("No devices yet."));
    assert!(
        !html.contains("All 20 devices in the inventory"),
        "the clamp dropped the filter and fell back to the whole inventory"
    );
    assert!(
        html.contains("match this filter"),
        "the filter must survive the clamp"
    );
}

#[tokio::test]
async fn the_clear_filters_link_returns_to_an_unfiltered_view() {
    let f = fixture().await;
    seed(&f.state, 20).await;
    let (_, html) = get(f.state.clone(), "/devices?q=nothing-matches-this").await;

    let marker = "Clear filters";
    assert!(html.contains(marker));
    // The cleared URL keeps the sort and drops every filter.
    let cleared = query("/devices?sort=asset_tag&dir=asc");
    assert!(!cleared.is_filtered());
    assert!(html.contains("/devices?sort=asset_tag&amp;dir=asc"));
}

// ---------------------------------------------------------------------------
// Accessibility (D10 — a build constraint, not a later pass)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_sorted_column_is_the_only_one_marked_sorted() {
    let f = fixture().await;
    seed(&f.state, 5).await;
    let (_, html) = get(f.state.clone(), "/devices?sort=aue_date&dir=desc").await;

    assert_eq!(
        html.matches(r#"aria-sort="descending""#).count(),
        1,
        "exactly one column may claim the sort"
    );
    assert_eq!(html.matches(r#"aria-sort="ascending""#).count(), 0);
    assert!(html.contains(r#"aria-sort="none""#), "others must say none");
    // Sort state also has a visible channel.
    assert!(html.contains("th-sort__arrow"));
}

/// WCAG 2.4.4: a link's name has to describe what following it does. "Asset
/// tag" read from a links list says nothing about sorting.
#[tokio::test]
async fn sort_links_are_named_for_the_action_not_the_column() {
    let f = fixture().await;
    seed(&f.state, 5).await;

    let (_, html) = get(f.state.clone(), "/devices?sort=asset_tag&dir=asc").await;
    assert!(
        html.contains(r#"aria-label="Sort by Asset tag, descending""#),
        "the sorted column's link must offer the flip"
    );
    assert!(
        html.contains(r#"aria-label="Sort by Serial, ascending""#),
        "an unsorted column's link must offer ascending"
    );
}

#[tokio::test]
async fn every_row_checkbox_names_its_row() {
    let f = fixture().await;
    seed(&f.state, 5).await;
    let (_, html) = get(f.state.clone(), "/devices").await;

    assert_eq!(html.matches("data-row-check").count(), 5);
    for i in 1..=5 {
        assert!(
            html.contains(&format!(r#"aria-label="Select device CB-{i:05}""#)),
            "row {i}'s checkbox has no accessible name"
        );
    }
    assert!(html.contains(r#"aria-label="Pick every device on this page""#));
}

/// A device with no tag still needs a name a screen reader can distinguish.
#[test]
fn a_row_with_no_asset_tag_falls_back_to_its_serial() {
    let today = NaiveDate::from_ymd_opt(2026, 7, 25).unwrap();
    let mut a = Asset::new("dev-x");
    a.serial_number = Some("SN9".into());
    let view = DeviceRowView::from_row(&AssetRow::bare(a.clone()), today);
    assert_eq!(view.check_label, "Select device SN9");

    a.serial_number = None;
    let view = DeviceRowView::from_row(&AssetRow::bare(a), today);
    assert_eq!(
        view.check_label, "Select device dev-x",
        "never a bare 'Select'"
    );
}

#[tokio::test]
async fn the_table_is_named_and_its_caption_says_it_is_filtered() {
    let f = fixture().await;
    seed(&f.state, 20).await;

    let (_, html) = get(f.state.clone(), "/devices").await;
    assert!(html.contains("Devices — 20 results"));
    assert!(!html.contains("results, filtered"));

    let (_, html) = get(f.state.clone(), "/devices?status=repair").await;
    assert!(
        html.contains("results, filtered"),
        "caption hides the filter"
    );
}

/// §5.12: an HTMX swap is silent to a screen reader without the announcement
/// bus, so every region response carries an out-of-band update.
#[tokio::test]
async fn every_swap_announces_its_result_through_the_live_region() {
    let f = fixture().await;
    seed(&f.state, 20).await;

    let (status, html) = get_htmx(f.state.clone(), "/devices?status=repair").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"id="announcer""#));
    assert!(html.contains(r#"hx-swap-oob="true""#));
    assert!(html.contains("devices match. Showing"));

    let (_, html) = get_htmx(f.state.clone(), "/devices?q=nothing").await;
    assert!(html.contains("No devices match these filters."));
}

/// The bus is one element with one id. A full page already has it from
/// base.html, so the region must not emit its out-of-band copy inline —
/// assistive technology watches the first match, which would be the one
/// nothing ever updates, and every later announcement would be silent.
#[tokio::test]
async fn a_full_page_carries_exactly_one_announcer() {
    let f = fixture().await;
    seed(&f.state, 5).await;

    let (_, page) = get(f.state.clone(), "/devices").await;
    assert_eq!(
        page.matches(r#"id="announcer""#).count(),
        1,
        "duplicate announcer id would silence the live region"
    );
    assert!(
        !page.contains(r#"hx-swap-oob="true""#),
        "a full page has nothing to swap out of band"
    );

    let (_, region) = get_htmx(f.state.clone(), "/devices").await;
    assert_eq!(region.matches(r#"id="announcer""#).count(), 1);
    assert!(region.contains(r#"hx-swap-oob="true""#));
}

#[test]
fn announcements_stay_inside_the_length_budget() {
    // §5.12 caps announcements at ~120 characters — long enough to state a
    // result, short enough not to be a paragraph read aloud on every keystroke.
    for total in [0i64, 1, 412, 20_000] {
        let view = DevicesView {
            rows: Vec::new(),
            nav: TableNav {
                base_path: DEVICES_PATH.into(),
                region_id: REGION_ID.into(),
                filter_pairs: Vec::new(),
                sort: "asset_tag".into(),
                direction: "asc".into(),
                page: 1,
                per_page: 100,
                total,
            },
            selection: Selection::new(SelectionMode::Matching, &[], total, 0),
            query: DevicesQuery::default(),
            schools: Vec::new(),
            status_options: Vec::new(),
            assigned_options: Vec::new(),
            total_unfiltered: total,
            matched_count: 0,
            unmatched_count: 0,
            csrf_token: String::new(),
            aue_soon_months: AUE_SOON_MONTHS,
            oob_announcer: true,
        };
        let announcement = view.announcement();
        assert!(!announcement.is_empty());
        assert!(
            announcement.len() <= 120,
            "announcement is {} chars: {announcement}",
            announcement.len()
        );
    }
}

// ---------------------------------------------------------------------------
// HTMX region contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_htmx_request_gets_the_region_and_a_navigation_gets_the_document() {
    let f = fixture().await;
    seed(&f.state, 5).await;

    let (_, page) = get(f.state.clone(), "/devices").await;
    assert!(
        page.contains("<!DOCTYPE html>"),
        "a navigation needs the shell"
    );
    assert!(page.contains("sidebar-nav"), "and the console chrome");

    let (_, region) = get_htmx(f.state.clone(), "/devices").await;
    assert!(
        !region.contains("<!DOCTYPE html>"),
        "a swap must not nest a document"
    );
    assert!(!region.contains("sidebar-nav"));
    assert!(region.contains(r#"id="devices-region""#));
    // Both render the same table, from the same template.
    assert!(page.contains(r#"id="devices-region""#));
    assert!(region.contains("CB-00001") && page.contains("CB-00001"));
}

/// §5.4: a filtered view is a URL. Without `hx-push-url` the address bar would
/// lag the table and nothing would be bookmarkable or shareable.
#[tokio::test]
async fn the_region_pushes_its_url_so_views_are_bookmarkable() {
    let f = fixture().await;
    seed(&f.state, 5).await;
    let (_, html) = get_htmx(f.state.clone(), "/devices?status=repair").await;
    assert!(html.contains(r#"hx-push-url="true""#));
    assert!(html.contains("hx-target=\"#devices-region\""));
}

/// The whole page has to work with scripting off, so every control is a real
/// link or a real form before HTMX touches it.
#[tokio::test]
async fn every_control_works_without_javascript() {
    let f = fixture().await;
    seed(&f.state, 300).await;
    let (_, html) = get(f.state.clone(), "/devices?status=repair&per_page=50").await;

    assert!(
        html.contains(r#"<form class="table-toolbar" method="get" action="/devices""#),
        "the filter toolbar is not a real GET form"
    );
    // Sort headers and pagination are anchors carrying an href, not buttons
    // whose behaviour lives only in a script.
    assert!(html.contains(r#"<a id="sort-asset_tag""#));
    assert!(html.contains(r#"href="/devices?status=repair&amp;sort=asset_tag&amp;dir=desc"#));
    assert!(html.contains(r#"class="pagination__page" href="/devices?"#));
}

#[tokio::test]
async fn the_search_box_debounces_rather_than_firing_per_keystroke() {
    let f = fixture().await;
    seed(&f.state, 5).await;
    let (_, html) = get(f.state.clone(), "/devices").await;
    assert!(html.contains(r#"hx-trigger="input changed delay:300ms, search""#));
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

#[tokio::test]
async fn devices_appears_in_the_sidebar_and_is_marked_current() {
    let f = fixture().await;
    seed(&f.state, 1).await;
    let (_, html) = get(f.state.clone(), "/devices").await;
    assert!(html.contains(r#"<a href="/devices" class="sidebar-link active">"#));

    let (_, other) = get(f.state.clone(), "/users").await;
    assert!(other.contains(r#"<a href="/devices" class="sidebar-link">"#));
}

/// An embedder that has not wired an asset repository gets an explanation, not
/// a panic or a 500.
#[tokio::test]
async fn the_inventory_says_so_when_it_is_not_enabled() {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let config = chalk_core::config::ChalkConfig::generate_default();
    let state = Arc::new(AppState::new(Arc::new(repo), config));

    let (status, html) = get(state, "/devices").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(html.contains("not enabled"));
}

#[tokio::test]
async fn the_school_filter_lists_schools_and_not_the_district() {
    let f = fixture().await;
    seed(&f.state, 4).await;
    let (_, html) = get(f.state.clone(), "/devices?school=org-hs").await;

    assert!(html.contains(r#"<option value="org-hs" selected>Springfield High</option>"#));
    assert!(html.contains(r#"<option value="org-ms">Shelbyville Middle</option>"#));
    assert!(
        !html.contains("Springfield District"),
        "a district is not a school and must not be offered as one"
    );
}

#[tokio::test]
async fn the_google_owned_columns_are_marked_and_the_marking_is_explained() {
    let f = fixture().await;
    seed(&f.state, 3).await;
    let (_, html) = get(f.state.clone(), "/devices").await;
    assert!(html.contains("col-google"));
    assert!(html.contains("come from Google Workspace and are edited there"));
}
