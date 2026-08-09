//! Asset inventory model (migration 019).
//!
//! An asset is a physical device. The load-bearing field is
//! [`Asset::assigned_user_sourced_id`], which references `users(sourced_id)`
//! from migration 001: school, grade, homeroom and guardian context are one
//! JOIN away from the roster the SIS sync already populates, and nothing about
//! a device's owner is ever re-entered.
//!
//! Assets are never hard-deleted. Retirement is a status change, which is why
//! `asset_events.asset_id` can be `ON DELETE RESTRICT` and why
//! [`AssetRepository`](crate::db::repository::AssetRepository) has no delete
//! method.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use super::page::SortDirection;
use super::str_enum::str_enum;

str_enum! {
    /// Physical kind of device.
    pub enum AssetType {
        #[default]
        Chromebook => "chromebook",
        Laptop => "laptop",
        Tablet => "tablet",
        Projector => "projector",
        Hotspot => "hotspot",
        Other => "other",
    }
    with_default
}

str_enum! {
    /// Lifecycle state. `Deprovisioned` is the Google-side terminal state and
    /// is distinct from `Retired`, which is purely local bookkeeping.
    pub enum AssetStatus {
        #[default]
        Active => "active",
        Repair => "repair",
        Storage => "storage",
        Retired => "retired",
        Deprovisioned => "deprovisioned",
        Lost => "lost",
    }
    with_default
}

str_enum! {
    /// Where the row came from. Governs which fields a sync may overwrite.
    pub enum AssetSource {
        Google => "google",
        Csv => "csv",
        #[default]
        Manual => "manual",
        Api => "api",
        Intune => "intune",
        Jamf => "jamf",
    }
    with_default
}

str_enum! {
    /// Roster-matching outcome for a synced device.
    ///
    /// `Manual` means a human set the assignment and no matcher may overwrite
    /// it. `Ignored` means a human decided this device will never match — it
    /// stays out of the unmatched queue permanently.
    pub enum MatchState {
        Matched => "matched",
        Unmatched => "unmatched",
        #[default]
        Manual => "manual",
        Ignored => "ignored",
    }
    with_default
}

/// One cell of a fleet breakdown: how many devices a school holds in a status.
///
/// `school_org_sourced_id` is `None` for devices belonging to no school, which
/// is a real and interesting group rather than noise — an unplaced device is
/// usually one nobody is responsible for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetGroupCount {
    pub school_org_sourced_id: Option<String>,
    pub status: AssetStatus,
    pub count: i64,
}

/// A row of `assets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    /// UUID.
    pub id: String,
    pub asset_tag: Option<String>,
    pub serial_number: Option<String>,
    pub asset_type: AssetType,
    pub make: Option<String>,
    pub model: Option<String>,
    pub status: AssetStatus,
    pub school_org_sourced_id: Option<String>,
    pub assigned_user_sourced_id: Option<String>,
    pub org_unit_path: Option<String>,
    pub source: AssetSource,
    pub match_state: MatchState,
    /// Directory API `deviceId`. `None` for non-Google assets. Unique when set.
    pub google_device_id: Option<String>,
    /// The device id in whatever non-Google MDM this row came from (Intune,
    /// Jamf). `source` says which. Google rows keep `google_device_id`.
    pub external_id: Option<String>,
    pub annotated_user: Option<String>,
    pub annotated_asset_id: Option<String>,
    pub aue_date: Option<NaiveDate>,
    pub os_version: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_known_ip: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    /// Integer cents. Money never goes through a float.
    pub purchase_cost_cents: Option<i64>,
    pub funding_source: Option<String>,
    pub warranty_expires: Option<NaiveDate>,
    /// Who sold it, for warranty claims and reorders (GP-3).
    pub vendor: Option<String>,
    /// The purchase order this device was received against, matched by
    /// number to a `purchase_orders` row when one exists.
    pub po_number: Option<String>,
    pub location: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Asset {
    /// A minimal asset with a caller-supplied id. All optional fields empty,
    /// enums at their defaults, timestamps `now`.
    pub fn new(id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            asset_tag: None,
            serial_number: None,
            asset_type: AssetType::default(),
            make: None,
            model: None,
            status: AssetStatus::default(),
            school_org_sourced_id: None,
            assigned_user_sourced_id: None,
            org_unit_path: None,
            source: AssetSource::default(),
            match_state: MatchState::default(),
            google_device_id: None,
            external_id: None,
            annotated_user: None,
            annotated_asset_id: None,
            aue_date: None,
            os_version: None,
            last_sync_at: None,
            last_known_ip: None,
            purchase_date: None,
            purchase_cost_cents: None,
            funding_source: None,
            warranty_expires: None,
            vendor: None,
            po_number: None,
            location: None,
            notes: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// True when the device is assigned to a roster user.
    pub fn is_assigned(&self) -> bool {
        self.assigned_user_sourced_id.is_some()
    }

    /// True when the device's auto-update expiration has passed as of `today`.
    pub fn is_past_aue(&self, today: NaiveDate) -> bool {
        self.aue_date.is_some_and(|aue| aue < today)
    }
}

/// One field of a partial update.
///
/// A plain `Option<T>` cannot express "set this nullable column to NULL"
/// distinctly from "leave it alone", and every device write-back needs both:
/// unassigning a device *is* writing NULL. Hence three states.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Patch<T> {
    /// Leave the column as-is.
    #[default]
    Unchanged,
    /// Write this value.
    Set(T),
    /// Write SQL NULL.
    Clear,
}

impl<T> Patch<T> {
    pub fn is_unchanged(&self) -> bool {
        matches!(self, Patch::Unchanged)
    }

    /// `Set(v)` for `Some(v)`, `Clear` for `None`. Use when the caller has a
    /// complete desired value including its absence.
    pub fn from_option(value: Option<T>) -> Self {
        match value {
            Some(v) => Patch::Set(v),
            None => Patch::Clear,
        }
    }

    /// The value to store: `None` means SQL NULL. Returns `None` for
    /// `Unchanged` too, so only call this after checking `is_unchanged`.
    pub fn as_option(&self) -> Option<&T> {
        match self {
            Patch::Set(v) => Some(v),
            Patch::Unchanged | Patch::Clear => None,
        }
    }
}

/// A value bound into a generated `UPDATE ... SET` clause.
///
/// The patch is rendered by a dialect-specific builder — SQLite uses `?n` and
/// stringified timestamps, Postgres uses `$n` and native types — but the
/// column list and its order come from [`AssetPatch::changes`] so the two
/// drivers cannot disagree about which columns a patch touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchValue {
    Null,
    Text(String),
    Int(i64),
    Date(NaiveDate),
    Timestamp(DateTime<Utc>),
}

/// A partial update to a row of `assets`. Every field defaults to
/// [`Patch::Unchanged`] / `None`, so `AssetPatch::default()` is a no-op.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AssetPatch {
    // NOT NULL columns: `None` means unchanged, there is no NULL to write.
    pub asset_type: Option<AssetType>,
    pub status: Option<AssetStatus>,
    pub source: Option<AssetSource>,
    pub match_state: Option<MatchState>,

    // Nullable columns.
    pub asset_tag: Patch<String>,
    pub serial_number: Patch<String>,
    pub make: Patch<String>,
    pub model: Patch<String>,
    pub school_org_sourced_id: Patch<String>,
    pub assigned_user_sourced_id: Patch<String>,
    pub org_unit_path: Patch<String>,
    pub google_device_id: Patch<String>,
    pub external_id: Patch<String>,
    pub annotated_user: Patch<String>,
    pub annotated_asset_id: Patch<String>,
    pub aue_date: Patch<NaiveDate>,
    pub os_version: Patch<String>,
    pub last_sync_at: Patch<DateTime<Utc>>,
    pub last_known_ip: Patch<String>,
    pub purchase_date: Patch<NaiveDate>,
    pub purchase_cost_cents: Patch<i64>,
    pub funding_source: Patch<String>,
    pub warranty_expires: Patch<NaiveDate>,
    pub vendor: Patch<String>,
    pub po_number: Patch<String>,
    pub location: Patch<String>,
    pub notes: Patch<String>,
}

/// Push one nullable column into the change list if it is not `Unchanged`.
///
/// `pub(crate)` so the ticket patch reuses it: two hand-rolled versions of
/// "a Clear binds NULL and an Unchanged binds nothing" is two places to get it
/// wrong.
pub(crate) fn push_patch<T, F>(
    out: &mut Vec<(&'static str, PatchValue)>,
    col: &'static str,
    p: &Patch<T>,
    f: F,
) where
    F: Fn(&T) -> PatchValue,
{
    match p {
        Patch::Unchanged => {}
        Patch::Clear => out.push((col, PatchValue::Null)),
        Patch::Set(v) => out.push((col, f(v))),
    }
}

impl AssetPatch {
    /// The columns this patch writes, in a stable order, with their bound
    /// values. `updated_at` is NOT included — each driver stamps it itself so
    /// the timestamp is the driver's own `now`.
    ///
    /// An empty result means the patch is a no-op and no `UPDATE` should run.
    pub fn changes(&self) -> Vec<(&'static str, PatchValue)> {
        let mut out: Vec<(&'static str, PatchValue)> = Vec::new();

        if let Some(v) = self.asset_type {
            out.push(("asset_type", PatchValue::Text(v.as_str().to_string())));
        }
        if let Some(v) = self.status {
            out.push(("status", PatchValue::Text(v.as_str().to_string())));
        }
        if let Some(v) = self.source {
            out.push(("source", PatchValue::Text(v.as_str().to_string())));
        }
        if let Some(v) = self.match_state {
            out.push(("match_state", PatchValue::Text(v.as_str().to_string())));
        }

        let text = |s: &String| PatchValue::Text(s.clone());
        push_patch(&mut out, "asset_tag", &self.asset_tag, text);
        push_patch(&mut out, "serial_number", &self.serial_number, text);
        push_patch(&mut out, "make", &self.make, text);
        push_patch(&mut out, "model", &self.model, text);
        push_patch(
            &mut out,
            "school_org_sourced_id",
            &self.school_org_sourced_id,
            text,
        );
        push_patch(
            &mut out,
            "assigned_user_sourced_id",
            &self.assigned_user_sourced_id,
            text,
        );
        push_patch(&mut out, "org_unit_path", &self.org_unit_path, text);
        push_patch(&mut out, "google_device_id", &self.google_device_id, text);
        push_patch(&mut out, "external_id", &self.external_id, text);
        push_patch(&mut out, "annotated_user", &self.annotated_user, text);
        push_patch(
            &mut out,
            "annotated_asset_id",
            &self.annotated_asset_id,
            text,
        );
        push_patch(&mut out, "aue_date", &self.aue_date, |d| {
            PatchValue::Date(*d)
        });
        push_patch(&mut out, "os_version", &self.os_version, text);
        push_patch(&mut out, "last_sync_at", &self.last_sync_at, |t| {
            PatchValue::Timestamp(*t)
        });
        push_patch(&mut out, "last_known_ip", &self.last_known_ip, text);
        push_patch(&mut out, "purchase_date", &self.purchase_date, |d| {
            PatchValue::Date(*d)
        });
        push_patch(
            &mut out,
            "purchase_cost_cents",
            &self.purchase_cost_cents,
            |c| PatchValue::Int(*c),
        );
        push_patch(&mut out, "funding_source", &self.funding_source, text);
        push_patch(&mut out, "warranty_expires", &self.warranty_expires, |d| {
            PatchValue::Date(*d)
        });
        push_patch(&mut out, "location", &self.location, text);
        push_patch(&mut out, "vendor", &self.vendor, text);
        push_patch(&mut out, "po_number", &self.po_number, text);
        push_patch(&mut out, "notes", &self.notes, text);

        out
    }

    /// True when applying this patch would change nothing.
    pub fn is_empty(&self) -> bool {
        self.changes().is_empty()
    }
}

str_enum! {
    /// Whitelisted sort column for asset listings. A closed enum, so the
    /// `ORDER BY` clause can never carry caller-supplied text.
    pub enum AssetSort {
        #[default]
        UpdatedAt => "updated_at",
        CreatedAt => "created_at",
        AssetTag => "asset_tag",
        SerialNumber => "serial_number",
        Model => "model",
        Status => "status",
        AueDate => "aue_date",
        OrgUnitPath => "org_unit_path",
        LastSyncAt => "last_sync_at",
    }
    with_default
}

impl AssetSort {
    /// The literal column name. Identical to [`AssetSort::as_str`], named
    /// separately so the SQL-interpolation site reads as deliberate.
    pub fn as_sql_column(&self) -> &'static str {
        self.as_str()
    }
}

/// Filters for [`AssetRepository::list_assets`](crate::db::repository::AssetRepository::list_assets).
///
/// Everything here is pushed into the `WHERE` clause. Nothing is filtered in
/// Rust after the fact — at 20k devices that is the difference between a page
/// load and a timeout.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AssetFilter {
    pub status: Option<AssetStatus>,
    pub asset_type: Option<AssetType>,
    pub source: Option<AssetSource>,
    pub match_state: Option<MatchState>,
    pub school_org_sourced_id: Option<String>,
    /// Restrict to devices at any of these schools.
    ///
    /// Separate from the single-school filter above, which is the operator's
    /// own choice from a dropdown. This one carries an **authorization**
    /// boundary — the schools a scoped API token may see — and the two compose:
    /// a token scoped to three schools that filters to one gets the
    /// intersection, never the union.
    ///
    /// Empty means no restriction. It exists so the boundary can be pushed into
    /// SQL rather than applied to rows after they are fetched: filtering in
    /// Rust means the database already returned data the caller may not read,
    /// and the pagination count is computed over rows they cannot see.
    pub school_org_sourced_ids: Vec<String>,
    /// With the IN-list above: also match devices whose school is NULL.
    ///
    /// `school IN (…)` excludes NULL on its own, which is the right default
    /// for a scoped principal — the unassigned pool is district property.
    /// This flag is the explicit per-user grant that widens the boundary to
    /// include it (GP-2 `include_unscoped`). Meaningless without the IN-list.
    pub include_unscoped_school: bool,
    pub assigned_user_sourced_id: Option<String>,
    /// Matches devices at or below this OU path.
    pub org_unit_path_prefix: Option<String>,
    /// `Some(true)` = only devices assigned to a roster user
    /// (`assigned_user_sourced_id IS NOT NULL`), `Some(false)` = only
    /// unassigned devices. `None` = no constraint.
    pub assigned: Option<bool>,
    /// Only devices whose `aue_date` is strictly before this date.
    pub aue_before: Option<NaiveDate>,
    /// Case-insensitive substring over asset tag, serial, annotated user and
    /// annotated asset id.
    pub search: Option<String>,
    pub sort: AssetSort,
    pub direction: SortDirection,
}

impl AssetFilter {
    /// The `ORDER BY` clause for this filter, optionally qualified by a table
    /// alias (`"a."`) so the same ordering can be applied to a join over a
    /// windowed subquery.
    ///
    /// Every part is a closed enum or a caller literal from the database
    /// layer — [`AssetSort`] and [`SortDirection`] exist precisely so this
    /// string can be interpolated without ever carrying user input. `id` is
    /// the tiebreaker that keeps paging stable when the sort column ties.
    ///
    /// Lives here rather than in each driver so SQLite and Postgres cannot
    /// drift on sort column, direction or tiebreaker.
    pub fn order_by_sql(&self, alias: &str) -> String {
        let dir = self.direction.as_sql();
        format!(
            "ORDER BY {alias}{} {dir}, {alias}id {dir}",
            self.sort.as_sql_column()
        )
    }

    /// The unmatched queue: synced devices a human has not resolved.
    pub fn unmatched() -> Self {
        Self {
            match_state: Some(MatchState::Unmatched),
            ..Self::default()
        }
    }
}

/// An asset together with the roster context the device inventory renders
/// beside it: the person the device is assigned to, and their school.
///
/// This type exists so the inventory page costs **one** query instead of one
/// per row. [`Asset`] carries only `assigned_user_sourced_id` and
/// `school_org_sourced_id`; resolving those per row is precisely the N+1 that
/// [`AssetRepository`](crate::db::repository::AssetRepository)'s doc comment
/// forbids, and at a 250-row page it is 500 extra round trips.
///
/// The joined fields are all `Option` because the join is a `LEFT JOIN`: an
/// unassigned device has no user, and a device whose school is unknown has no
/// org. They are flattened rather than holding a `User`/`Org` because the table
/// renders four strings and hydrating two full models per row would read the
/// whole roster into memory to paint a name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetRow {
    pub asset: Asset,
    pub assigned_given_name: Option<String>,
    pub assigned_family_name: Option<String>,
    pub assigned_email: Option<String>,
    pub school_name: Option<String>,
}

impl AssetRow {
    /// An asset with no roster context — the shape an unassigned device takes.
    pub fn bare(asset: Asset) -> Self {
        Self {
            asset,
            assigned_given_name: None,
            assigned_family_name: None,
            assigned_email: None,
            school_name: None,
        }
    }

    /// `"Family, Given"` for the student column, or `None` when the device is
    /// unassigned. Sorting-order presentation ("Last, First") is deliberate:
    /// a technician scans this column against an alphabetical roster.
    pub fn assigned_display_name(&self) -> Option<String> {
        match (&self.assigned_family_name, &self.assigned_given_name) {
            (Some(family), Some(given)) => Some(format!("{family}, {given}")),
            (Some(family), None) => Some(family.clone()),
            (None, Some(given)) => Some(given.clone()),
            (None, None) => None,
        }
    }
}

str_enum! {
    /// What kind of principal performed an action.
    pub enum ActorKind {
        Admin => "admin",
        Technician => "technician",
        ApiToken => "api_token",
        System => "system",
    }
}

str_enum! {
    /// The append-only event vocabulary for `asset_events`.
    pub enum AssetEventType {
        Assigned => "assigned",
        Unassigned => "unassigned",
        MovedOu => "moved_ou",
        StatusChanged => "status_changed",
        Deprovisioned => "deprovisioned",
        Repaired => "repaired",
        Imported => "imported",
        FieldChanged => "field_changed",
    }
}

/// An event to append. Has no `id` and no `created_at` — the database assigns
/// both, which is what makes the log append-only rather than authored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAssetEvent {
    pub asset_id: String,
    /// `users.sourced_id`, an API token prefix, or `system:google-sync`.
    pub actor: String,
    pub actor_kind: ActorKind,
    pub event_type: AssetEventType,
    pub payload: Option<serde_json::Value>,
}

impl NewAssetEvent {
    /// A field-level change event with the conventional
    /// `{"field":…,"old":…,"new":…}` payload.
    pub fn field_changed(
        asset_id: impl Into<String>,
        actor: impl Into<String>,
        actor_kind: ActorKind,
        field: &str,
        old: Option<&str>,
        new: Option<&str>,
    ) -> Self {
        Self {
            asset_id: asset_id.into(),
            actor: actor.into(),
            actor_kind,
            event_type: AssetEventType::FieldChanged,
            payload: Some(serde_json::json!({
                "field": field,
                "old": old,
                "new": new,
            })),
        }
    }

    /// An event carrying no structured payload.
    pub fn simple(
        asset_id: impl Into<String>,
        actor: impl Into<String>,
        actor_kind: ActorKind,
        event_type: AssetEventType,
    ) -> Self {
        Self {
            asset_id: asset_id.into(),
            actor: actor.into(),
            actor_kind,
            event_type,
            payload: None,
        }
    }
}

/// A persisted row of `asset_events`. Immutable by construction: there is no
/// update or delete anywhere in the repository layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetEvent {
    pub id: i64,
    pub asset_id: String,
    pub actor: String,
    pub actor_kind: ActorKind,
    pub event_type: AssetEventType,
    pub payload: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Filters for
/// [`AssetEventRepository::list_events`](crate::db::repository::AssetEventRepository::list_events).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AssetEventFilter {
    pub asset_id: Option<String>,
    pub event_type: Option<AssetEventType>,
    pub actor: Option<String>,
    /// Events belonging to devices currently at this school.
    ///
    /// Resolved through a subquery against `assets`, because `asset_events`
    /// holds no school of its own. That has a consequence worth stating: the
    /// filter follows a device's **present** school, not the school it was at
    /// when the event happened. A Chromebook moved between buildings takes its
    /// whole history with it.
    ///
    /// That is the right default for the question this filter answers — "what
    /// has happened to my school's devices" — and the alternative would mean
    /// denormalising a school onto every event row, freezing a value that the
    /// roster sync legitimately changes.
    pub school_org_sourced_id: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl AssetEventFilter {
    /// The history tab for one device.
    pub fn for_asset(asset_id: impl Into<String>) -> Self {
        Self {
            asset_id: Some(asset_id.into()),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn enum_strings_match_the_migration_comments() {
        assert_eq!(AssetType::Chromebook.as_str(), "chromebook");
        assert_eq!(AssetStatus::Deprovisioned.as_str(), "deprovisioned");
        assert_eq!(AssetSource::Google.as_str(), "google");
        assert_eq!(MatchState::Unmatched.as_str(), "unmatched");
        assert_eq!(ActorKind::ApiToken.as_str(), "api_token");
        assert_eq!(AssetEventType::MovedOu.as_str(), "moved_ou");
    }

    #[test]
    fn enum_defaults_match_the_ddl_defaults() {
        assert_eq!(AssetType::default().as_str(), "chromebook");
        assert_eq!(AssetStatus::default().as_str(), "active");
        assert_eq!(AssetSource::default().as_str(), "manual");
        assert_eq!(MatchState::default().as_str(), "manual");
    }

    #[test]
    fn every_enum_round_trips() {
        for v in AssetType::ALL {
            assert_eq!(&AssetType::parse(v.as_str()).unwrap(), v);
        }
        for v in AssetStatus::ALL {
            assert_eq!(&AssetStatus::parse(v.as_str()).unwrap(), v);
        }
        for v in AssetSource::ALL {
            assert_eq!(&AssetSource::parse(v.as_str()).unwrap(), v);
        }
        for v in MatchState::ALL {
            assert_eq!(&MatchState::parse(v.as_str()).unwrap(), v);
        }
        for v in ActorKind::ALL {
            assert_eq!(&ActorKind::parse(v.as_str()).unwrap(), v);
        }
        for v in AssetEventType::ALL {
            assert_eq!(&AssetEventType::parse(v.as_str()).unwrap(), v);
        }
        for v in AssetSort::ALL {
            assert_eq!(&AssetSort::parse(v.as_str()).unwrap(), v);
        }
    }

    #[test]
    fn unknown_enum_value_fails_closed() {
        assert!(AssetStatus::parse("ACTIVE").is_err());
        assert!(AssetStatus::parse("").is_err());
    }

    #[test]
    fn new_asset_is_a_valid_default_row() {
        let a = Asset::new("asset-1");
        assert_eq!(a.id, "asset-1");
        assert_eq!(a.status, AssetStatus::Active);
        assert!(!a.is_assigned());
        assert!(!a.is_past_aue(date(2030, 1, 1)));
    }

    #[test]
    fn is_past_aue_compares_strictly() {
        let mut a = Asset::new("a");
        a.aue_date = Some(date(2026, 6, 1));
        assert!(a.is_past_aue(date(2026, 6, 2)));
        assert!(!a.is_past_aue(date(2026, 6, 1)));
        assert!(!a.is_past_aue(date(2026, 5, 31)));
    }

    #[test]
    fn default_patch_is_a_no_op() {
        let p = AssetPatch::default();
        assert!(p.is_empty());
        assert!(p.changes().is_empty());
    }

    #[test]
    fn patch_distinguishes_clear_from_unchanged() {
        let p = AssetPatch {
            assigned_user_sourced_id: Patch::Clear,
            ..AssetPatch::default()
        };
        let changes = p.changes();
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0],
            ("assigned_user_sourced_id", PatchValue::Null),
            "unassigning must emit an explicit NULL write, not be skipped"
        );

        let q = AssetPatch {
            assigned_user_sourced_id: Patch::Unchanged,
            ..AssetPatch::default()
        };
        assert!(q.changes().is_empty());
    }

    #[test]
    fn patch_emits_typed_values_per_column() {
        let p = AssetPatch {
            status: Some(AssetStatus::Repair),
            purchase_cost_cents: Patch::Set(24_999),
            aue_date: Patch::Set(date(2029, 6, 30)),
            notes: Patch::Set("cracked screen".to_string()),
            ..AssetPatch::default()
        };

        let changes = p.changes();
        assert_eq!(
            changes,
            vec![
                ("status", PatchValue::Text("repair".to_string())),
                ("aue_date", PatchValue::Date(date(2029, 6, 30))),
                ("purchase_cost_cents", PatchValue::Int(24_999)),
                ("notes", PatchValue::Text("cracked screen".to_string())),
            ]
        );
    }

    #[test]
    fn patch_never_emits_updated_at() {
        let p = AssetPatch {
            status: Some(AssetStatus::Lost),
            last_sync_at: Patch::Set(Utc::now()),
            ..AssetPatch::default()
        };
        assert!(
            !p.changes().iter().any(|(c, _)| *c == "updated_at"),
            "each driver stamps updated_at with its own now()"
        );
    }

    #[test]
    fn patch_from_option_maps_none_to_clear() {
        assert_eq!(Patch::from_option(Some(3_i64)), Patch::Set(3));
        assert_eq!(Patch::<i64>::from_option(None), Patch::Clear);
    }

    #[test]
    fn field_changed_event_uses_the_conventional_payload() {
        let e = NewAssetEvent::field_changed(
            "asset-1",
            "user-9",
            ActorKind::Admin,
            "status",
            Some("active"),
            Some("repair"),
        );
        assert_eq!(e.event_type, AssetEventType::FieldChanged);
        let payload = e.payload.unwrap();
        assert_eq!(payload["field"], "status");
        assert_eq!(payload["old"], "active");
        assert_eq!(payload["new"], "repair");
    }

    #[test]
    fn unmatched_filter_targets_the_queue() {
        let f = AssetFilter::unmatched();
        assert_eq!(f.match_state, Some(MatchState::Unmatched));
        assert_eq!(f.sort, AssetSort::UpdatedAt);
        assert_eq!(f.direction, SortDirection::Asc);
    }

    #[test]
    fn sort_columns_are_real_column_names() {
        // Guards against a rename drifting away from the DDL.
        let columns = [
            "updated_at",
            "created_at",
            "asset_tag",
            "serial_number",
            "model",
            "status",
            "aue_date",
            "org_unit_path",
            "last_sync_at",
        ];
        let actual: Vec<&str> = AssetSort::ALL.iter().map(|s| s.as_sql_column()).collect();
        assert_eq!(actual, columns);
    }

    #[test]
    fn order_by_sql_qualifies_both_the_sort_column_and_the_tiebreaker() {
        let f = AssetFilter {
            sort: AssetSort::AueDate,
            direction: SortDirection::Desc,
            ..Default::default()
        };
        assert_eq!(f.order_by_sql(""), "ORDER BY aue_date DESC, id DESC");
        // The alias form is what a join over a windowed subquery needs; both
        // forms must name the same column and the same tiebreaker.
        assert_eq!(f.order_by_sql("a."), "ORDER BY a.aue_date DESC, a.id DESC");
    }

    #[test]
    fn order_by_sql_covers_every_sort_column() {
        // The interpolation is only safe because both halves are closed enums.
        // If a variant ever renders something that is not a bare identifier,
        // this catches it before it reaches a query.
        for sort in AssetSort::ALL {
            let f = AssetFilter {
                sort: *sort,
                ..Default::default()
            };
            let clause = f.order_by_sql("");
            assert_eq!(
                clause,
                format!("ORDER BY {} ASC, id ASC", sort.as_sql_column())
            );
            assert!(clause
                .trim_start_matches("ORDER BY ")
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " _,.".contains(c)));
        }
    }

    #[test]
    fn assigned_display_name_is_family_then_given() {
        let row = AssetRow {
            asset: Asset::new("a"),
            assigned_given_name: Some("John".into()),
            assigned_family_name: Some("Doe".into()),
            assigned_email: Some("jdoe@example.com".into()),
            school_name: Some("Springfield High".into()),
        };
        assert_eq!(row.assigned_display_name().as_deref(), Some("Doe, John"));
    }

    #[test]
    fn assigned_display_name_is_none_for_an_unassigned_device() {
        assert_eq!(
            AssetRow::bare(Asset::new("a")).assigned_display_name(),
            None
        );
    }

    /// A roster row missing half its name still renders something a technician
    /// can read, rather than a stray comma.
    #[test]
    fn assigned_display_name_tolerates_a_half_populated_name() {
        let mut row = AssetRow::bare(Asset::new("a"));
        row.assigned_family_name = Some("Doe".into());
        assert_eq!(row.assigned_display_name().as_deref(), Some("Doe"));

        let mut row = AssetRow::bare(Asset::new("a"));
        row.assigned_given_name = Some("John".into());
        assert_eq!(row.assigned_display_name().as_deref(), Some("John"));
    }

    #[test]
    fn asset_serializes_camel_case() {
        let a = Asset::new("asset-1");
        let json = serde_json::to_value(&a).unwrap();
        assert!(json.get("assignedUserSourcedId").is_some());
        assert!(json.get("googleDeviceId").is_some());
        assert_eq!(json["assetType"], "chromebook");
    }
}
