//! Manual create/edit tests.
//!
//! Two properties carry the most weight: a hand-added device must not land in
//! the unmatched queue asking to be resolved, and a Google-owned field must not
//! be editable here — offering it would offer a change the next sync reverts.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, ChalkRepository, OrgRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::asset::{AssetEventFilter, AssetSource};
use chalk_core::models::common::Status;
use chalk_core::models::org::Org;
use chalk_core::models::page::PageRequest;
use chrono::{TimeZone, Utc};
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
    repo.upsert_org(&Org {
        sourced_id: "org-1".into(),
        status: Status::Active,
        date_last_modified: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        metadata: None,
        name: "Springfield High".into(),
        org_type: OrgType::School,
        identifier: None,
        parent: None,
        children: vec![],
    })
    .await
    .unwrap();

    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, ChalkConfig::generate_default()).with_assets(assets, events),
    );
    Fx { state, repo }
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

async fn post(state: Arc<AppState>, uri: &str, body: &str) -> (StatusCode, String) {
    let token = crate::csrf::generate_csrf_token();
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, location)
}

// ---------------------------------------------------------------------------
// Creating
// ---------------------------------------------------------------------------

/// The point of the whole feature: something Google does not manage can now
/// exist in the inventory.
#[tokio::test]
async fn a_device_google_does_not_manage_can_be_added() {
    let f = fixture().await;
    let (status, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_tag=PROJ-1&asset_type=projector&status=active&school=org-1&location=Room+12",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let id = location.rsplit('/').next().unwrap();
    let asset = f.repo.get_asset(id).await.unwrap().unwrap();
    assert_eq!(asset.asset_type, AssetType::Projector);
    assert_eq!(asset.asset_tag.as_deref(), Some("PROJ-1"));
    assert_eq!(asset.location.as_deref(), Some("Room 12"));
    assert_eq!(asset.source, AssetSource::Manual);
    assert_eq!(asset.google_device_id, None);
}

/// Every non-Chromebook type is reachable. Before this, five of the six
/// variants existed in the enum and could never be produced.
#[tokio::test]
async fn every_asset_type_can_be_created() {
    let f = fixture().await;
    for (i, ty) in [
        "chromebook",
        "laptop",
        "tablet",
        "projector",
        "hotspot",
        "other",
    ]
    .iter()
    .enumerate()
    {
        let (status, location) = post(
            f.state.clone(),
            NEW_PATH,
            &format!("asset_tag=T-{i}&asset_type={ty}&status=active"),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{ty} was refused");
        let id = location.rsplit('/').next().unwrap();
        assert_eq!(
            f.repo.get_asset(id).await.unwrap().unwrap().asset_type,
            AssetType::parse(ty).unwrap()
        );
    }
}

/// A hand-added device must not appear in the unmatched queue. Nobody is
/// expected to own a projector, and a queue that asks about it is a queue that
/// never empties.
#[tokio::test]
async fn a_hand_added_device_does_not_land_in_the_unmatched_queue() {
    let f = fixture().await;
    let (_, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_tag=PROJ-1&asset_type=projector&status=active",
    )
    .await;
    let id = location.rsplit('/').next().unwrap();

    assert_eq!(
        f.repo.get_asset(id).await.unwrap().unwrap().match_state,
        MatchState::Manual,
        "it did not come from a matcher, so it is not unmatched"
    );

    let (_, queue) = get(f.state.clone(), "/devices/unmatched").await;
    assert!(!queue.contains("PROJ-1"));
}

/// It appears in its own history from the first moment, rather than seeming to
/// come from nowhere.
#[tokio::test]
async fn creating_a_device_records_that_it_was_added_by_hand() {
    let f = fixture().await;
    let (_, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_tag=PROJ-1&asset_type=projector&status=active",
    )
    .await;
    let id = location.rsplit('/').next().unwrap().to_string();

    let events = f
        .repo
        .list_events(&AssetEventFilter::for_asset(&id), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(events.total, 1);
    assert_eq!(
        events.items[0].payload.as_ref().unwrap()["source"],
        "added by hand"
    );
}

/// A device with neither a tag nor a serial cannot be looked up by anyone
/// holding it, which makes it a row rather than an asset.
#[tokio::test]
async fn a_device_with_no_identifier_is_refused() {
    let f = fixture().await;
    let (status, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_type=laptop&status=active&make=Dell",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("err="), "it must say why");

    let all = f
        .repo
        .list_assets(&Default::default(), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(all.total, 0, "nothing was created");
}

/// Serials are unique in the schema, so a duplicate must be a sentence rather
/// than a raw database error.
#[tokio::test]
async fn a_duplicate_serial_is_refused_with_an_explanation() {
    let f = fixture().await;
    post(
        f.state.clone(),
        NEW_PATH,
        "serial_number=SN-1&asset_type=laptop&status=active",
    )
    .await;

    let (status, location) = post(
        f.state.clone(),
        NEW_PATH,
        "serial_number=SN-1&asset_type=tablet&status=active",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("already"), "got: {location}");

    let all = f
        .repo
        .list_assets(&Default::default(), PageRequest::new(10, 0))
        .await
        .unwrap();
    assert_eq!(all.total, 1);
}

#[tokio::test]
async fn a_nonsense_type_or_status_is_refused() {
    let f = fixture().await;
    for body in [
        "asset_tag=X&asset_type=spaceship&status=active",
        "asset_tag=X&asset_type=laptop&status=exploded",
    ] {
        let (_, location) = post(f.state.clone(), NEW_PATH, body).await;
        assert!(location.contains("err="), "{body} was accepted");
    }
    assert_eq!(
        f.repo
            .list_assets(&Default::default(), PageRequest::new(10, 0))
            .await
            .unwrap()
            .total,
        0
    );
}

// ---------------------------------------------------------------------------
// Editing
// ---------------------------------------------------------------------------

async fn google_device(f: &Fx, id: &str) {
    let mut a = Asset::new(id);
    a.asset_tag = Some("CB-1".into());
    a.serial_number = Some("SN-G1".into());
    a.google_device_id = Some("g-1".into());
    a.annotated_user = Some("jane@example.edu".into());
    a.org_unit_path = Some("/Students".into());
    f.repo.create_asset(&a).await.unwrap();
}

/// Google owns some fields on a synced device. Offering them would offer a
/// change the next sync silently reverts, so the form says so instead.
#[tokio::test]
async fn google_owned_fields_are_read_only_on_a_synced_device() {
    let f = fixture().await;
    google_device(&f, "g-asset").await;

    let (status, html) = get(f.state.clone(), "/devices/g-asset/edit").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("came from Google Workspace"));
    assert!(html.contains("would be overwritten by the next sync"));
    // The values are shown, but not as inputs.
    assert!(html.contains("jane@example.edu"));
    assert!(
        !html.contains(r#"name="annotated_user""#),
        "a Google-owned field must not be an editable input"
    );
    assert!(
        !html.contains(r#"name="org_unit_path""#),
        "the org unit is Google's"
    );
}

/// A hand-added device has no such owner, so nothing is withheld.
#[tokio::test]
async fn a_hand_added_device_has_no_read_only_fields() {
    let f = fixture().await;
    let (_, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_tag=PROJ-1&asset_type=projector&status=active",
    )
    .await;
    let id = location.rsplit('/').next().unwrap();

    let (_, html) = get(f.state.clone(), &format!("/devices/{id}/edit")).await;
    assert!(!html.contains("came from Google Workspace"));
}

/// An edit changes the device and says which fields moved, so the history is
/// readable without diffing two versions by hand.
#[tokio::test]
async fn editing_records_which_fields_changed() {
    let f = fixture().await;
    let (_, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_tag=PROJ-1&asset_type=projector&status=active",
    )
    .await;
    let id = location.rsplit('/').next().unwrap().to_string();

    let (status, _) = post(
        f.state.clone(),
        &format!("/devices/{id}/edit"),
        "asset_tag=PROJ-2&asset_type=projector&status=repair&make=Epson",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let asset = f.repo.get_asset(&id).await.unwrap().unwrap();
    assert_eq!(asset.asset_tag.as_deref(), Some("PROJ-2"));
    assert_eq!(asset.status, AssetStatus::Repair);
    assert_eq!(asset.make.as_deref(), Some("Epson"));

    let events = f
        .repo
        .list_events(&AssetEventFilter::for_asset(&id), PageRequest::new(10, 0))
        .await
        .unwrap();
    // Creation plus the edit.
    assert_eq!(events.total, 2);
    let edit = &events.items[0];
    assert_eq!(edit.event_type, AssetEventType::StatusChanged);
    let fields = edit.payload.as_ref().unwrap()["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(fields.contains(&"asset_tag".to_string()));
    assert!(fields.contains(&"status".to_string()));
    assert!(fields.contains(&"make".to_string()));
    assert!(
        !fields.contains(&"model".to_string()),
        "a field that did not change must not be listed"
    );
}

/// Every editable field must be audited.
///
/// An audit that lists only some of what changed is worse than one saying
/// "edited": it looks precise while being wrong. This caught `location` and
/// the purchase fields being omitted — an end-to-end edit reported a status
/// change while the location had moved too.
#[tokio::test]
async fn every_editable_field_appears_in_the_audit_when_it_changes() {
    let f = fixture().await;
    let (_, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_tag=A&serial_number=S1&asset_type=laptop&status=active&make=M1&model=D1\
         &school=org-1&notes=N1&location=L1&funding_source=F1&purchase_date=2024-01-01\
         &warranty_expires=2027-01-01",
    )
    .await;
    let id = location.rsplit('/').next().unwrap().to_string();

    // Change every one of them.
    post(
        f.state.clone(),
        &format!("/devices/{id}/edit"),
        "asset_tag=B&serial_number=S2&asset_type=tablet&status=repair&make=M2&model=D2\
         &school=&notes=N2&location=L2&funding_source=F2&purchase_date=2025-02-02\
         &warranty_expires=2028-02-02",
    )
    .await;

    let events = f
        .repo
        .list_events(&AssetEventFilter::for_asset(&id), PageRequest::new(10, 0))
        .await
        .unwrap();
    let fields: Vec<String> = events.items[0].payload.as_ref().unwrap()["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for expected in [
        "asset_tag",
        "serial_number",
        "asset_type",
        "status",
        "make",
        "model",
        "school",
        "notes",
        "location",
        "funding_source",
        "purchase_date",
        "warranty_expires",
    ] {
        assert!(
            fields.contains(&expected.to_string()),
            "{expected} changed but was not audited. Audited: {fields:?}"
        );
    }

    // And the values actually moved, not just the audit.
    let asset = f.repo.get_asset(&id).await.unwrap().unwrap();
    assert_eq!(asset.location.as_deref(), Some("L2"));
    assert_eq!(asset.funding_source.as_deref(), Some("F2"));
    assert_eq!(
        asset.purchase_date.map(|d| d.to_string()).as_deref(),
        Some("2025-02-02")
    );
}

/// Clearing a field means clearing it. Leaving the old value would make
/// "delete the text and save" do nothing, which is worse than refusing.
#[tokio::test]
async fn emptying_a_field_clears_it() {
    let f = fixture().await;
    let (_, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_tag=PROJ-1&asset_type=projector&status=active&notes=fragile",
    )
    .await;
    let id = location.rsplit('/').next().unwrap().to_string();

    post(
        f.state.clone(),
        &format!("/devices/{id}/edit"),
        "asset_tag=PROJ-1&asset_type=projector&status=active&notes=",
    )
    .await;

    assert_eq!(f.repo.get_asset(&id).await.unwrap().unwrap().notes, None);
}

/// A serial may move to another device only if no other device holds it.
#[tokio::test]
async fn an_edit_cannot_steal_another_devices_serial() {
    let f = fixture().await;
    google_device(&f, "g-asset").await;
    let (_, location) = post(
        f.state.clone(),
        NEW_PATH,
        "asset_tag=PROJ-1&asset_type=projector&status=active",
    )
    .await;
    let id = location.rsplit('/').next().unwrap().to_string();

    let (_, redirect) = post(
        f.state.clone(),
        &format!("/devices/{id}/edit"),
        "asset_tag=PROJ-1&serial_number=SN-G1&asset_type=projector&status=active",
    )
    .await;
    assert!(redirect.contains("err="), "got: {redirect}");
    assert_eq!(
        f.repo.get_asset(&id).await.unwrap().unwrap().serial_number,
        None
    );
}

#[tokio::test]
async fn editing_a_missing_device_is_a_404() {
    let f = fixture().await;
    let (status, _) = get(f.state.clone(), "/devices/nope/edit").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The inventory offers a way in, so the feature is reachable rather than a
/// URL someone has to know.
#[tokio::test]
async fn the_inventory_links_to_adding_a_device() {
    let f = fixture().await;
    let (_, html) = get(f.state.clone(), "/devices").await;
    assert!(html.contains("/devices/new"));
}
