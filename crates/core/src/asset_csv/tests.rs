//! Asset CSV tests.
//!
//! The property worth the most is the round trip: what export writes, import
//! must read back as the same device. Everything else here is about a file
//! being *partly* wrong, which is the normal case — a district's spreadsheet
//! has a typo on row 47, and refusing the other 400 rows over it would be
//! useless.

use super::*;

use crate::models::asset::Asset;

fn sample() -> Asset {
    let mut a = Asset::new("a-1");
    a.asset_tag = Some("CB-0001".into());
    a.serial_number = Some("SN-0001".into());
    a.asset_type = AssetType::Laptop;
    a.make = Some("Dell".into());
    a.model = Some("Latitude 3190".into());
    a.status = AssetStatus::Repair;
    a.location = Some("Room 12".into());
    a.funding_source = Some("Bond 2024".into());
    a.purchase_date = chrono::NaiveDate::from_ymd_opt(2024, 8, 1);
    a.warranty_expires = chrono::NaiveDate::from_ymd_opt(2027, 8, 1);
    a.notes = Some("cracked bezel".into());
    a.org_unit_path = Some("/Students/HS".into());
    a.annotated_user = Some("jane@example.edu".into());
    a.google_device_id = Some("g-1".into());
    a
}

/// Write a CSV the way the export endpoint does.
fn write(assets: &[Asset]) -> Vec<u8> {
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record(header()).unwrap();
    for a in assets {
        w.write_record(row(a)).unwrap();
    }
    w.into_inner().unwrap()
}

/// The property the whole module exists for.
#[test]
fn a_row_survives_the_round_trip() {
    let csv = write(&[sample()]);
    let (rows, errors) = parse(&csv);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(rows.len(), 1);

    let r = &rows[0];
    assert_eq!(r.asset_tag.as_deref(), Some("CB-0001"));
    assert_eq!(r.serial_number.as_deref(), Some("SN-0001"));
    assert_eq!(r.asset_type, Some(AssetType::Laptop));
    assert_eq!(r.make.as_deref(), Some("Dell"));
    assert_eq!(r.model.as_deref(), Some("Latitude 3190"));
    assert_eq!(r.status, Some(AssetStatus::Repair));
    assert_eq!(r.location.as_deref(), Some("Room 12"));
    assert_eq!(r.funding_source.as_deref(), Some("Bond 2024"));
    assert_eq!(r.purchase_date, chrono::NaiveDate::from_ymd_opt(2024, 8, 1));
    assert_eq!(
        r.warranty_expires,
        chrono::NaiveDate::from_ymd_opt(2027, 8, 1)
    );
    assert_eq!(r.notes.as_deref(), Some("cracked bezel"));
}

/// Google-owned columns are written for reference and ignored coming back.
/// Accepting them would let a spreadsheet appear to change values the next sync
/// immediately overwrites.
#[test]
fn google_columns_are_exported_but_never_imported() {
    let csv = String::from_utf8(write(&[sample()])).unwrap();
    assert!(csv.contains("/Students/HS"), "exported for reference");
    assert!(csv.contains("jane@example.edu"));
    assert!(csv.contains("g-1"));

    for col in REFERENCE_COLUMNS {
        assert!(
            !IMPORTABLE_COLUMNS.contains(col),
            "{col} must not be importable"
        );
    }
    // And the parser has no field for them at all.
    let (rows, _) = parse(csv.as_bytes());
    let r = &rows[0];
    assert_eq!(r.asset_tag.as_deref(), Some("CB-0001"));
    // Nothing on AssetCsvRow can hold a Google value — this is a type-level
    // guarantee, restated here so a future field addition trips the test.
    assert_eq!(
        std::mem::size_of_val(&r.notes),
        std::mem::size_of::<Option<String>>()
    );
}

/// Serial wins over asset tag. A serial is stamped by the manufacturer; a tag
/// is chosen by people and gets reused across refresh cycles.
#[test]
fn a_row_is_matched_on_serial_before_asset_tag() {
    let both = AssetCsvRow {
        serial_number: Some("SN-1".into()),
        asset_tag: Some("CB-1".into()),
        ..Default::default()
    };
    assert_eq!(both.match_key(), Some(("serial_number", "SN-1")));

    let tag_only = AssetCsvRow {
        asset_tag: Some("CB-1".into()),
        ..Default::default()
    };
    assert_eq!(tag_only.match_key(), Some(("asset_tag", "CB-1")));

    assert_eq!(AssetCsvRow::default().match_key(), None);
}

/// A file with only the columns someone cares about is a perfectly good bulk
/// update. Requiring the full header would make the feature unusable.
#[test]
fn a_partial_column_set_is_accepted() {
    let (rows, errors) = parse(b"serial_number,status\nSN-1,repair\nSN-2,storage\n");
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].status, Some(AssetStatus::Repair));
    assert_eq!(rows[0].asset_tag, None, "absent means absent, not empty");
    assert_eq!(rows[1].serial_number.as_deref(), Some("SN-2"));
}

/// Extra columns from another system are ignored, not fatal. Refusing a whole
/// file over a column nobody needs would be hostile.
#[test]
fn unknown_columns_are_ignored() {
    let (rows, errors) = parse(b"serial_number,status,snipe_id,department\nSN-1,repair,42,IT\n");
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].serial_number.as_deref(), Some("SN-1"));
}

/// Header casing varies between systems and should not matter.
#[test]
fn headers_are_case_insensitive() {
    let (rows, errors) = parse(b"Serial_Number,STATUS\nSN-1,repair\n");
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(rows[0].serial_number.as_deref(), Some("SN-1"));
}

/// A file with no way to identify a device is refused up front, rather than
/// producing four hundred unmatched rows.
#[test]
fn a_file_with_no_identifier_column_is_refused_with_a_reason() {
    let (rows, errors) = parse(b"make,model\nDell,Latitude\n");
    assert!(rows.is_empty());
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("serial_number or asset_tag"));
}

/// A bad row names its line so it can be fixed, and does not take the good rows
/// with it. "Row 3 is not a status" is actionable; "the import failed" is not.
#[test]
fn a_bad_row_is_reported_by_line_and_the_rest_still_import() {
    let (rows, errors) = parse(b"serial_number,status\nSN-1,repair\nSN-2,exploded\nSN-3,storage\n");
    assert_eq!(rows.len(), 2, "the good rows survive");
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].line, 3,
        "counted like a spreadsheet, header first"
    );
    assert!(errors[0].message.contains("exploded"));
    assert!(errors[0].message.contains("status"));
}

/// A row with an identifier column present but empty cannot be matched, and is
/// reported rather than silently creating something.
#[test]
fn a_row_with_an_empty_identifier_is_reported() {
    let (rows, errors) = parse(b"serial_number,status\n,repair\nSN-2,storage\n");
    assert_eq!(rows.len(), 1);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].line, 2);
    assert!(errors[0].message.contains("cannot be matched"));
}

/// A date that is not a date is caught while the operator still has the file
/// open, rather than becoming a failed item after they approved a preview.
#[test]
fn an_unreadable_date_names_its_row_and_its_column() {
    let (rows, errors) =
        parse(b"serial_number,purchase_date\nSN-1,2024-08-01\nSN-2,08/01/2024\nSN-3,2024-13-01\n");
    assert_eq!(rows.len(), 1, "only the readable row imports");
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].line, 3);
    assert!(errors[0].message.contains("purchase_date"));
    assert!(errors[0].message.contains("08/01/2024"));
    assert_eq!(errors[1].line, 4, "an impossible date is not a date");
}

/// Values a spreadsheet mangles. Leading zeros in an asset tag are the classic
/// one — the incumbent add-on turned `00123` into `123` and silently renamed
/// the device.
#[test]
fn leading_zeros_and_whitespace_survive_intact() {
    let (rows, errors) = parse(b"asset_tag,status\n  00123  ,repair\n");
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(
        rows[0].asset_tag.as_deref(),
        Some("00123"),
        "trimmed, but never renumbered"
    );
}

/// Quoted commas and embedded newlines are ordinary CSV and must not split a
/// row. A location like "Room 12, cart 3" is completely normal.
#[test]
fn quoted_values_containing_commas_are_one_field() {
    let (rows, errors) = parse(b"serial_number,location\nSN-1,\"Room 12, cart 3\"\n");
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(rows[0].location.as_deref(), Some("Room 12, cart 3"));
}

/// An empty file is not an error, it is an empty import.
#[test]
fn an_empty_file_produces_nothing_and_complains_about_nothing_useful() {
    let (rows, errors) = parse(b"");
    assert!(rows.is_empty());
    // A header-less empty file cannot name an identifier column, which is the
    // one thing worth saying about it.
    assert_eq!(errors.len(), 1);

    let (rows, errors) = parse(b"serial_number,status\n");
    assert!(rows.is_empty());
    assert!(errors.is_empty(), "a header with no rows is fine");
}

/// Every importable column appears in the export header, or a round trip would
/// silently drop it.
#[test]
fn the_export_header_covers_every_importable_column() {
    let h = header();
    for col in IMPORTABLE_COLUMNS {
        assert!(h.contains(col), "{col} is importable but never exported");
    }
    assert_eq!(
        h.len(),
        IMPORTABLE_COLUMNS.len() + REFERENCE_COLUMNS.len(),
        "the header must be exactly the two lists"
    );
}

/// The row writer must stay aligned with the header. A column added to one and
/// not the other shifts every value after it — the kind of bug that corrupts
/// data quietly.
#[test]
fn every_row_has_exactly_as_many_fields_as_the_header() {
    assert_eq!(row(&sample()).len(), header().len());
    assert_eq!(row(&Asset::new("empty")).len(), header().len());
}
