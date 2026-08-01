//! CSV import planning tests.
//!
//! Two properties carry the feature. **A re-import of an unedited export must
//! change nothing** — that is what makes the round trip trustworthy, and the
//! whole reason export and import share a column list. And **nothing the
//! planner is unsure about may be written**: an ambiguous tag, a duplicate
//! row, an unreadable date. Each has to come back naming its line.
//!
//! The rest is about what a spreadsheet must *not* be able to do — chiefly
//! erase a field it simply did not mention.

use super::*;

use crate::asset_csv;
use crate::change_commit::commit_change_set;
use crate::db::repository::AssetEventRepository;
use crate::db::sqlite::SqliteRepository;
use crate::db::DatabasePool;
use crate::models::asset::{AssetEventFilter, AssetStatus, AssetType};
use crate::models::change_set::ChangeSetItemStatus;
use crate::models::page::PageRequest;

struct Fx {
    assets: Arc<dyn AssetRepository>,
    sets: Arc<dyn ChangeSetRepository>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    Fx {
        assets: repo.clone(),
        sets: repo.clone(),
        repo,
    }
}

/// One device already in the inventory.
async fn device(f: &Fx, id: &str) -> Asset {
    let mut a = Asset::new(id);
    a.asset_tag = Some(format!("CB-{id}"));
    a.serial_number = Some(format!("SN-{id}"));
    a.status = AssetStatus::Active;
    a.location = Some("Room 12".into());
    a.notes = Some("original note".into());
    f.repo.create_asset(&a).await.unwrap();
    a
}

async fn plan(f: &Fx, csv: &[u8]) -> CsvImportPlan {
    let (rows, errors) = asset_csv::parse(csv);
    plan_csv_import(&f.assets, &f.sets, &rows, &errors, "admin")
        .await
        .unwrap()
}

async fn items(f: &Fx, id: &str) -> Vec<crate::models::change_set::ChangeSetItem> {
    f.sets
        .list_items(id, None, PageRequest::new(200, 0))
        .await
        .unwrap()
        .items
}

/// Apply a plan the way the job runner does.
async fn commit(f: &Fx, plan: &CsvImportPlan) -> crate::change_commit::CommitOutcome {
    let set = f
        .sets
        .get_change_set(&plan.change_set_id)
        .await
        .unwrap()
        .unwrap();
    commit_change_set(
        &f.sets,
        &plan.change_set_id,
        &set.plan_hash,
        set.expected_item_count,
        "admin",
    )
    .await
    .unwrap()
    .unwrap()
}

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

/// Export, import the file back untouched, and nothing changes. This is the
/// property the shared column list exists to guarantee, and the one an
/// operator will test first.
#[tokio::test]
async fn re_importing_an_unedited_export_changes_nothing() {
    let f = fixture().await;
    let a = device(&f, "a").await;

    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record(asset_csv::header()).unwrap();
    w.write_record(asset_csv::row(&a)).unwrap();
    let file = w.into_inner().unwrap();

    let p = plan(&f, &file).await;
    assert_eq!(p.item_count, 0, "nothing to do");
    assert_eq!(p.unchanged_count, 1);
    assert_eq!(p.created_count, 0, "it matched, so nothing is created");
    assert!(p.rejected.is_empty(), "{:?}", p.rejected);
}

// ---------------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------------

/// One item per changed field, so a technician can strike out the location
/// change without abandoning the status change beside it.
#[tokio::test]
async fn a_changed_row_produces_one_item_per_changed_field() {
    let f = fixture().await;
    device(&f, "a").await;

    let p = plan(
        &f,
        b"serial_number,status,location,notes\nSN-a,repair,Room 14,original note\n",
    )
    .await;

    assert_eq!(p.updated_count, 1);
    assert_eq!(
        p.item_count, 2,
        "status and location — the note is identical"
    );

    let fields: Vec<String> = items(&f, &p.change_set_id)
        .await
        .iter()
        .filter_map(|i| i.field.clone())
        .collect();
    assert!(fields.contains(&"status".to_string()));
    assert!(fields.contains(&"location".to_string()));
    assert!(!fields.contains(&"notes".to_string()));
}

/// An absent column means "unchanged", never "clear this". A file with only
/// `serial_number,status` must not erase every note and location in a fleet.
#[tokio::test]
async fn a_column_the_file_omits_is_left_alone() {
    let f = fixture().await;
    device(&f, "a").await;

    let p = plan(&f, b"serial_number,status\nSN-a,repair\n").await;
    commit(&f, &p).await;

    let after = f.assets.get_asset("a").await.unwrap().unwrap();
    assert_eq!(after.status, AssetStatus::Repair);
    assert_eq!(
        after.notes.as_deref(),
        Some("original note"),
        "a column the file never mentioned survives"
    );
    assert_eq!(after.location.as_deref(), Some("Room 12"));
}

/// An empty *cell* in a column the file does carry is also "unchanged". A
/// spreadsheet full of blanks is the normal shape of a partial edit, and
/// treating blanks as deletions would make the feature a footgun.
#[tokio::test]
async fn an_empty_cell_does_not_clear_the_field() {
    let f = fixture().await;
    device(&f, "a").await;

    let p = plan(&f, b"serial_number,location,notes\nSN-a,,\n").await;
    assert_eq!(p.item_count, 0);
    assert_eq!(p.unchanged_count, 1);
}

/// Every importable column can actually be written. A field the planner
/// proposes but the commit path has no rule for would fail *after* approval,
/// which is the one moment it must not.
#[tokio::test]
async fn every_importable_column_survives_plan_and_commit() {
    let f = fixture().await;
    device(&f, "a").await;

    let p = plan(
        &f,
        b"serial_number,asset_tag,asset_type,make,model,status,location,\
          funding_source,purchase_date,warranty_expires,notes\n\
          SN-a,CB-new,tablet,Dell,Latitude 3190,repair,Room 14,Bond 2024,\
          2024-08-01,2027-08-01,cracked bezel\n",
    )
    .await;

    // Ten columns differ; `serial_number` is the match key and is unchanged.
    assert_eq!(p.item_count, 10, "one per changed column");
    let outcome = commit(&f, &p).await;
    assert_eq!(outcome.applied, 10);
    assert_eq!(outcome.failed, 0, "no column lacks a commit rule");

    let a = f.assets.get_asset("a").await.unwrap().unwrap();
    assert_eq!(a.asset_tag.as_deref(), Some("CB-new"));
    assert_eq!(a.asset_type, AssetType::Tablet);
    assert_eq!(a.make.as_deref(), Some("Dell"));
    assert_eq!(a.model.as_deref(), Some("Latitude 3190"));
    assert_eq!(a.status, AssetStatus::Repair);
    assert_eq!(a.location.as_deref(), Some("Room 14"));
    assert_eq!(a.funding_source.as_deref(), Some("Bond 2024"));
    assert_eq!(a.purchase_date, chrono::NaiveDate::from_ymd_opt(2024, 8, 1));
    assert_eq!(
        a.warranty_expires,
        chrono::NaiveDate::from_ymd_opt(2027, 8, 1)
    );
    assert_eq!(a.notes.as_deref(), Some("cracked bezel"));
}

// ---------------------------------------------------------------------------
// Creates
// ---------------------------------------------------------------------------

/// A row matching nothing brings a device into existence — that is how a
/// district's existing inventory gets in — and it is marked `csv` so its
/// origin is never in doubt.
#[tokio::test]
async fn a_row_matching_nothing_creates_a_device_marked_csv() {
    let f = fixture().await;

    let p = plan(
        &f,
        b"serial_number,asset_tag,status,location\nSN-new,CB-new,storage,Warehouse\n",
    )
    .await;
    assert_eq!(p.created_count, 1);
    assert_eq!(p.item_count, 1, "a create is one item, not one per column");

    let outcome = commit(&f, &p).await;
    assert_eq!(outcome.applied, 1);

    let made = f
        .assets
        .get_asset_by_serial("SN-new")
        .await
        .unwrap()
        .expect("the device exists");
    assert_eq!(made.asset_tag.as_deref(), Some("CB-new"));
    assert_eq!(made.status, AssetStatus::Storage);
    assert_eq!(made.location.as_deref(), Some("Warehouse"));
    assert_eq!(
        made.source,
        AssetSource::Csv,
        "where it came from is part of the record"
    );

    // And the audit trail says so, pointing at the device that now exists.
    let events = f
        .repo
        .list_events(
            &AssetEventFilter {
                asset_id: Some(made.id.clone()),
                ..Default::default()
            },
            PageRequest::new(10, 0),
        )
        .await
        .unwrap();
    assert_eq!(events.items.len(), 1);
    assert_eq!(
        events.items[0].event_type,
        crate::models::asset::AssetEventType::Imported
    );
    assert_eq!(
        events.items[0].payload.as_ref().unwrap()["via"],
        "csv_import"
    );
}

/// The created device's id is fixed at plan time and carried in the item, so
/// the change set item points at the row it actually made rather than a NULL.
#[tokio::test]
async fn a_create_item_ends_up_pointing_at_the_device_it_made() {
    let f = fixture().await;
    let p = plan(&f, b"serial_number\nSN-new\n").await;

    assert!(
        items(&f, &p.change_set_id).await[0].asset_id.is_none(),
        "nothing exists to point at while it is only a proposal"
    );

    commit(&f, &p).await;

    let item = &items(&f, &p.change_set_id).await[0];
    assert_eq!(item.status, ChangeSetItemStatus::Applied);
    let made = f
        .assets
        .get_asset_by_serial("SN-new")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(item.asset_id.as_deref(), Some(made.id.as_str()));
}

/// Re-importing a file that created devices matches them the second time
/// rather than making a second copy. This is the "matching by serial so a
/// re-import updates rather than duplicates" promise, tested end to end.
#[tokio::test]
async fn importing_the_same_file_twice_does_not_duplicate() {
    let f = fixture().await;
    let file = b"serial_number,status\nSN-new,storage\n";

    let first = plan(&f, file).await;
    assert_eq!(first.created_count, 1);
    commit(&f, &first).await;

    let second = plan(&f, file).await;
    assert_eq!(second.created_count, 0, "it matches now");
    assert_eq!(second.item_count, 0, "and has nothing to say");
    assert_eq!(second.unchanged_count, 1);
}

// ---------------------------------------------------------------------------
// What the planner refuses to guess at
// ---------------------------------------------------------------------------

/// Asset tags carry no unique index because districts reuse them. A tag on two
/// devices is genuinely ambiguous, and writing to whichever row the query
/// planner returned first would be a coin flip against a district's inventory.
#[tokio::test]
async fn a_tag_on_two_devices_is_reported_rather_than_guessed_at() {
    let f = fixture().await;
    for id in ["a", "b"] {
        let mut a = Asset::new(id);
        a.asset_tag = Some("CB-DUP".into());
        a.serial_number = Some(format!("SN-{id}"));
        f.repo.create_asset(&a).await.unwrap();
    }

    let p = plan(&f, b"asset_tag,status\nCB-DUP,repair\n").await;
    assert_eq!(p.item_count, 0, "nothing is written");
    assert_eq!(p.created_count, 0, "and nothing is created either");
    assert_eq!(p.rejected.len(), 1);
    assert_eq!(p.rejected[0].line, 2);
    assert!(p.rejected[0].message.contains("2 devices"));
}

/// Two rows for the same device would make the outcome depend on row order,
/// and for a create would try to make the same device twice.
#[tokio::test]
async fn a_duplicate_row_is_reported_and_only_the_first_is_planned() {
    let f = fixture().await;
    device(&f, "a").await;

    let p = plan(&f, b"serial_number,status\nSN-a,repair\nSN-a,storage\n").await;
    assert_eq!(p.item_count, 1);
    assert_eq!(p.rejected.len(), 1);
    assert_eq!(p.rejected[0].line, 3, "the later row is the one refused");

    let item = &items(&f, &p.change_set_id).await[0];
    assert_eq!(
        item.new_value.as_deref(),
        Some("repair"),
        "the first row wins, and which one won is stated"
    );
}

/// Rows the parser could not read at all land in the same list as rows the
/// planner refused, so the operator gets one account of what the file did not
/// do rather than two half-lists.
#[tokio::test]
async fn unreadable_rows_and_unmatchable_rows_are_reported_together() {
    let f = fixture().await;
    device(&f, "a").await;

    let p = plan(
        &f,
        b"serial_number,status\nSN-a,repair\nSN-b,exploded\n,storage\n",
    )
    .await;

    assert_eq!(p.item_count, 1, "only the good row is planned");
    assert_eq!(p.rejected.len(), 2);
    let lines: Vec<usize> = p.rejected.iter().map(|e| e.line).collect();
    assert_eq!(lines, vec![3, 4]);
}

/// Rejected rows travel with the change set, so the preview can show them
/// beside what will happen instead of losing them on a redirect.
#[tokio::test]
async fn rejected_rows_are_carried_in_the_change_set_summary() {
    let f = fixture().await;
    let p = plan(&f, b"serial_number,status\nSN-a,exploded\n").await;

    let set = f
        .sets
        .get_change_set(&p.change_set_id)
        .await
        .unwrap()
        .unwrap();
    let rejected = set.summary["rejectedRows"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["line"], 2);
    assert!(rejected[0]["message"]
        .as_str()
        .unwrap()
        .contains("exploded"));
    assert_eq!(set.summary["createdCount"], 0);
    assert_eq!(
        set.kind,
        crate::models::change_set::ChangeSetKind::CsvImport,
        "which entry point produced this is part of the record"
    );
}

/// A file larger than one plan may carry is truncated *and says so*. A preview
/// that quietly covers less than the file is the exact failure the whole phase
/// exists to prevent.
#[tokio::test]
async fn an_oversized_file_is_truncated_out_loud() {
    let f = fixture().await;
    let mut file = String::from("serial_number,status\n");
    for i in 0..(MAX_PLAN_ITEMS + 10) {
        file.push_str(&format!("SN-{i},storage\n"));
    }

    let p = plan(&f, file.as_bytes()).await;
    assert!(p.truncated);
    assert_eq!(p.item_count, MAX_PLAN_ITEMS);
}

/// The plan hash covers the created asset, so a change set whose create item
/// was altered between preview and commit is refused.
#[tokio::test]
async fn a_tampered_create_item_fails_the_staleness_guard() {
    let f = fixture().await;
    let p = plan(&f, b"serial_number,status\nSN-new,storage\n").await;

    let set = f
        .sets
        .get_change_set(&p.change_set_id)
        .await
        .unwrap()
        .unwrap();
    let refusal = commit_change_set(
        &f.sets,
        &p.change_set_id,
        "a-hash-from-some-other-plan",
        set.expected_item_count,
        "admin",
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(
        refusal,
        crate::change_commit::CommitRefusal::Stale { .. }
    ));
    assert!(
        f.assets
            .get_asset_by_serial("SN-new")
            .await
            .unwrap()
            .is_none(),
        "nothing was created"
    );
}
