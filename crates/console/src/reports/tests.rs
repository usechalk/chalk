//! Report tests.
//!
//! A report is a number someone repeats to a superintendent, so the property
//! that matters is that the arithmetic is right and the link under it shows
//! exactly the devices it counted. A band that says 47 and opens 51 is worse
//! than no report.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, OrgRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::Asset;
use chalk_core::models::common::Status;
use chalk_core::models::org::Org;
use chrono::TimeZone;
use tower::ServiceExt;

use crate::router;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    for (id, name) in [("org-a", "Alpha High"), ("org-b", "Beta Middle")] {
        repo.upsert_org(&Org {
            sourced_id: id.into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            name: name.into(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        })
        .await
        .unwrap();
    }
    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default()).with_assets(assets, events),
    );
    Fx { state, repo }
}

/// A device with an AUE date `months` from today, or none.
async fn device(
    f: &Fx,
    id: &str,
    school: Option<&str>,
    status: AssetStatus,
    aue_months: Option<i64>,
    assigned: Option<&str>,
) {
    let mut a = Asset::new(id);
    a.asset_tag = Some(format!("CB-{id}"));
    a.school_org_sourced_id = school.map(str::to_string);
    a.status = status;
    a.assigned_user_sourced_id = assigned.map(str::to_string);
    a.aue_date = aue_months.map(|m| add_months(Utc::now().date_naive(), m));
    f.repo.create_asset(&a).await.unwrap();
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
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

// ---------------------------------------------------------------------------
// Arithmetic
// ---------------------------------------------------------------------------

/// Bands are disjoint and they add up. They are computed as differences of
/// cumulative counts, which is exactly the sort of arithmetic that silently
/// double-counts a boundary device.
#[tokio::test]
async fn the_bands_are_disjoint_and_sum_to_the_fleet_with_a_known_expiry() {
    let f = fixture().await;
    device(&f, "past", None, AssetStatus::Active, Some(-6), None).await;
    device(&f, "soon", None, AssetStatus::Active, Some(6), None).await;
    device(&f, "y2", None, AssetStatus::Active, Some(18), None).await;
    device(&f, "y3", None, AssetStatus::Active, Some(30), None).await;
    device(&f, "none", None, AssetStatus::Active, None, None).await;

    let (status, body) = get(f.state.clone(), REPORTS_PATH).await;
    assert_eq!(status, StatusCode::OK);

    // One device in each of the four bands, and the one with no date is
    // reported separately rather than swallowed by the last band.
    assert!(body.contains("Already expired"));
    assert!(body.contains("No expiry recorded"));

    // The overdue banner names the single expired device.
    assert!(body.contains("1 device is past auto-update expiration"));
}

/// A device whose expiry is unknown is never counted as if it were far away.
/// Folding it into the last band would make a fleet look healthier than it is.
#[tokio::test]
async fn devices_with_no_expiry_are_reported_separately() {
    let f = fixture().await;
    for i in 0..3 {
        device(&f, &format!("u{i}"), None, AssetStatus::Active, None, None).await;
    }
    device(&f, "known", None, AssetStatus::Active, Some(30), None).await;

    let (_, body) = get(f.state.clone(), REPORTS_PATH).await;
    assert!(body.contains("No expiry recorded"));
    assert!(
        body.contains("has not told Chalk when these expire"),
        "and says why, since the fix is to sync"
    );
}

/// The school breakdown counts each device once, in its own school and status.
#[tokio::test]
async fn the_school_breakdown_counts_each_device_once() {
    let f = fixture().await;
    device(&f, "a1", Some("org-a"), AssetStatus::Active, None, None).await;
    device(&f, "a2", Some("org-a"), AssetStatus::Active, None, None).await;
    device(&f, "a3", Some("org-a"), AssetStatus::Repair, None, None).await;
    device(&f, "b1", Some("org-b"), AssetStatus::Lost, None, None).await;

    let (_, body) = get(f.state.clone(), REPORTS_PATH).await;
    assert!(body.contains("Alpha High"));
    assert!(body.contains("Beta Middle"));
    // Alpha's row links to its own filtered inventory.
    assert!(body.contains("school=org-a&amp;status=active") || body.contains("school=org-a"));
}

/// A device with no school is its own row, not dropped. An unplaced device is
/// usually one nobody is responsible for, which is the interesting case.
#[tokio::test]
async fn devices_with_no_school_get_their_own_row() {
    let f = fixture().await;
    device(&f, "x", None, AssetStatus::Active, None, None).await;

    let (_, body) = get(f.state.clone(), REPORTS_PATH).await;
    assert!(body.contains("No school"));
}

/// A device attached to an org that is not a school still gets a row.
///
/// The column references `orgs`, not schools, and `ON DELETE SET NULL` means
/// it can never dangle — so this, not a missing row, is the reachable oddity.
/// Blanking it would hide a device nobody could then chase.
#[tokio::test]
async fn a_device_attached_to_a_non_school_org_is_named_rather_than_blank() {
    let f = fixture().await;
    f.repo
        .upsert_org(&Org {
            sourced_id: "org-district".into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            name: "Springfield District".into(),
            org_type: OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        })
        .await
        .unwrap();
    device(
        &f,
        "odd",
        Some("org-district"),
        AssetStatus::Active,
        None,
        None,
    )
    .await;

    let (_, body) = get(f.state.clone(), REPORTS_PATH).await;
    assert!(body.contains("Not a school (org-district)"));
}

/// The unassigned figure counts devices with nobody attached, and links to
/// exactly that filter.
#[tokio::test]
async fn the_unassigned_figure_matches_the_filter_it_links_to() {
    let f = fixture().await;
    f.repo
        .upsert_user(&chalk_core::models::user::User {
            sourced_id: "u-1".into(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: "lisa".into(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Lisa".into(),
            family_name: "Simpson".into(),
            middle_name: None,
            role: chalk_core::models::common::RoleType::Student,
            identifier: None,
            email: None,
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec![],
            grades: vec![],
        })
        .await
        .unwrap();
    device(&f, "held", None, AssetStatus::Active, None, Some("u-1")).await;
    device(&f, "spare1", None, AssetStatus::Active, None, None).await;
    device(&f, "spare2", None, AssetStatus::Active, None, None).await;

    let (_, body) = get(f.state.clone(), REPORTS_PATH).await;
    assert!(body.contains("assigned=unassigned"));
    assert!(body.contains("of 3 devices"));
}

// ---------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------

/// An empty inventory says so rather than rendering three zeroed tables that
/// look like a broken page.
#[tokio::test]
async fn an_empty_fleet_says_there_is_nothing_to_report_on() {
    let f = fixture().await;
    let (status, body) = get(f.state.clone(), REPORTS_PATH).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("nothing to report on yet"));
    assert!(!body.contains("Replacement runway"));
}

/// A fleet with no expired devices does not show the alarm.
#[tokio::test]
async fn a_healthy_fleet_shows_no_overdue_banner() {
    let f = fixture().await;
    device(&f, "fine", None, AssetStatus::Active, Some(30), None).await;

    let (_, body) = get(f.state.clone(), REPORTS_PATH).await;
    assert!(!body.contains("past auto-update expiration"));
}

/// Month arithmetic never produces an invalid date. Adding a month to the 31st
/// is the classic panic, and it would take down a page nobody expects to be
/// risky.
#[test]
fn adding_months_never_lands_on_an_invalid_date() {
    for (y, m, d) in [
        (2026, 1, 31),
        (2026, 3, 31),
        (2026, 5, 31),
        (2026, 8, 31),
        (2024, 2, 29),
        (2026, 12, 31),
    ] {
        let from = NaiveDate::from_ymd_opt(y, m, d).unwrap();
        for months in [-24i64, -6, 0, 1, 6, 12, 24, 36, 600] {
            let got = add_months(from, months);
            assert!(got.year() > 2000, "{from} + {months} months produced {got}");
        }
    }
    // And it actually moves: a year out is a year out.
    let jan = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
    assert_eq!(add_months(jan, 12).year(), 2027);
    assert_eq!(add_months(jan, -1).month(), 12);
    assert_eq!(add_months(jan, -1).year(), 2025);
}

/// Reports go away with the module, like every other device route.
#[tokio::test]
async fn reports_are_gated_with_the_devices_module() {
    let f = fixture().await;
    let mut config = ChalkConfig::generate_default();
    config.modules.devices = false;
    let gated = Arc::new(AppState::new(f.state.repo.clone(), config).with_assets(
        f.state.assets.clone().unwrap(),
        f.state.asset_events.clone().unwrap(),
    ));

    let (status, _) = get(gated, REPORTS_PATH).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The band arithmetic itself, without a database or a rendered page.
///
/// Bands are differences of cumulative "expires before X" counts. Using the
/// cumulative totals directly is the natural mistake, and it inflates every
/// band after the first — a fleet of four would report 1, 2, 3, 4.
#[test]
fn bands_are_differences_of_cumulative_counts_not_the_totals() {
    let d = |m: i64| add_months(Utc::now().date_naive(), m);
    // One device in each band: 1 expired, 1 within 12, 1 within 24, 1 within 36.
    let cumulative = vec![(d(0), 1), (d(12), 2), (d(24), 3), (d(36), 4)];

    let bands = bands_from_cumulative(&cumulative);
    assert_eq!(bands.len(), 4);
    assert_eq!(
        bands.iter().map(|b| b.count).collect::<Vec<_>>(),
        vec![1, 1, 1, 1],
        "each band holds its own devices, not everything before it"
    );
    assert!(bands[0].overdue, "only the first band is overdue");
    assert!(!bands[1].overdue);
    assert_eq!(
        bands.iter().map(|b| b.count).sum::<i64>(),
        4,
        "and they sum to the fleet with a known expiry"
    );
}

/// An empty fleet produces zeroes, not negatives or a panic.
#[test]
fn bands_over_an_empty_fleet_are_all_zero() {
    let d = |m: i64| add_months(Utc::now().date_naive(), m);
    let bands = bands_from_cumulative(&[(d(0), 0), (d(12), 0), (d(24), 0), (d(36), 0)]);
    assert!(bands.iter().all(|b| b.count == 0));
}

/// Counts come from separate queries, so a device syncing between two of them
/// could make a later total smaller. A negative band would be nonsense on a
/// page someone reads aloud.
#[test]
fn a_shrinking_total_clamps_at_zero_rather_than_going_negative() {
    let d = |m: i64| add_months(Utc::now().date_naive(), m);
    let bands = bands_from_cumulative(&[(d(0), 5), (d(12), 3), (d(24), 9), (d(36), 9)]);
    assert!(
        bands.iter().all(|b| b.count >= 0),
        "no band may be negative: {:?}",
        bands.iter().map(|b| b.count).collect::<Vec<_>>()
    );
}
