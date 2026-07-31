//! The asset CSV contract — one column list, used by both export and import.
//!
//! # Why the two share a module
//!
//! A round trip has to be lossless: export a filtered view, edit it in a
//! spreadsheet, import it back, and get exactly what you meant. That is only
//! true if the writer and the reader agree on the columns, and the reliable way
//! to make them agree is to give them one definition rather than two that look
//! alike.
//!
//! # What is exported but not imported
//!
//! Google-owned columns — org unit, the annotated fields, AUE date, device id —
//! are written so a spreadsheet is a complete picture, and **ignored on the way
//! back in**. Accepting them would let a CSV appear to change values that the
//! next sync immediately overwrites, which is the same trap the edit form
//! avoids by making those fields read-only.
//!
//! # Why the export is the escape hatch
//!
//! An open-source product a district is weighing against Snipe-IT has to be
//! able to say "your data is yours, here it is". A filtered export is that
//! sentence in working form.

use crate::models::asset::{Asset, AssetStatus, AssetType};

/// Columns an import will read. Order is the export order.
pub const IMPORTABLE_COLUMNS: &[&str] = &[
    "asset_tag",
    "serial_number",
    "asset_type",
    "make",
    "model",
    "status",
    "location",
    "funding_source",
    "purchase_date",
    "warranty_expires",
    "notes",
];

/// Columns written for reference and ignored on import, because Google owns
/// them and the next sync would overwrite anything a spreadsheet set.
pub const REFERENCE_COLUMNS: &[&str] = &[
    "org_unit_path",
    "google_user",
    "aue_date",
    "google_device_id",
];

/// The full export header.
pub fn header() -> Vec<&'static str> {
    IMPORTABLE_COLUMNS
        .iter()
        .chain(REFERENCE_COLUMNS.iter())
        .copied()
        .collect()
}

/// One asset as an export row, in [`header`] order.
pub fn row(asset: &Asset) -> Vec<String> {
    let s = |v: &Option<String>| v.clone().unwrap_or_default();
    vec![
        s(&asset.asset_tag),
        s(&asset.serial_number),
        asset.asset_type.as_str().to_string(),
        s(&asset.make),
        s(&asset.model),
        asset.status.as_str().to_string(),
        s(&asset.location),
        s(&asset.funding_source),
        asset
            .purchase_date
            .map(|d| d.to_string())
            .unwrap_or_default(),
        asset
            .warranty_expires
            .map(|d| d.to_string())
            .unwrap_or_default(),
        s(&asset.notes),
        s(&asset.org_unit_path),
        s(&asset.annotated_user),
        asset.aue_date.map(|d| d.to_string()).unwrap_or_default(),
        s(&asset.google_device_id),
    ]
}

/// One parsed import row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetCsvRow {
    /// 1-based row number in the file, for error messages an operator can act
    /// on. "Row 47 has no serial" is fixable; "a row has no serial" is not.
    pub line: usize,
    pub asset_tag: Option<String>,
    pub serial_number: Option<String>,
    pub asset_type: Option<AssetType>,
    pub make: Option<String>,
    pub model: Option<String>,
    pub status: Option<AssetStatus>,
    pub location: Option<String>,
    pub funding_source: Option<String>,
    pub purchase_date: Option<String>,
    pub warranty_expires: Option<String>,
    pub notes: Option<String>,
}

impl AssetCsvRow {
    /// The identifier this row will be matched on.
    ///
    /// Serial first: it is stamped on the device by its manufacturer and is the
    /// one value a district cannot accidentally reuse. An asset tag is chosen
    /// by people and gets reused across refresh cycles.
    pub fn match_key(&self) -> Option<(&'static str, &str)> {
        if let Some(s) = self.serial_number.as_deref().filter(|v| !v.is_empty()) {
            return Some(("serial_number", s));
        }
        self.asset_tag
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(|t| ("asset_tag", t))
    }
}

/// A row that could not be read, named so it can be fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvRowError {
    pub line: usize,
    pub message: String,
}

/// Parse an asset CSV.
///
/// Unknown columns are ignored rather than rejected — a district's export from
/// another system will carry extras, and refusing the whole file over a column
/// nobody needs would be hostile. Missing columns are also fine: a file with
/// only `serial_number,status` is a perfectly good bulk status update.
///
/// Returns rows and per-row errors together, because a partial file is normal
/// and the operator needs to see both what will import and what will not.
pub fn parse(bytes: &[u8]) -> (Vec<AssetCsvRow>, Vec<CsvRowError>) {
    let mut rows = Vec::new();
    let mut errors = Vec::new();

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(bytes);

    let headers: Vec<String> = match reader.headers() {
        Ok(h) => h.iter().map(|s| s.to_ascii_lowercase()).collect(),
        Err(e) => {
            errors.push(CsvRowError {
                line: 1,
                message: format!("could not read the header row: {e}"),
            });
            return (rows, errors);
        }
    };

    let index_of = |name: &str| headers.iter().position(|h| h == name);
    let cols = ImportColumns {
        asset_tag: index_of("asset_tag"),
        serial_number: index_of("serial_number"),
        asset_type: index_of("asset_type"),
        make: index_of("make"),
        model: index_of("model"),
        status: index_of("status"),
        location: index_of("location"),
        funding_source: index_of("funding_source"),
        purchase_date: index_of("purchase_date"),
        warranty_expires: index_of("warranty_expires"),
        notes: index_of("notes"),
    };

    if cols.serial_number.is_none() && cols.asset_tag.is_none() {
        errors.push(CsvRowError {
            line: 1,
            message: "the file needs a serial_number or asset_tag column — without \
                      one there is no way to tell which device each row is about"
                .into(),
        });
        return (rows, errors);
    }

    for (i, record) in reader.records().enumerate() {
        // +2: one for the header, one to count from 1 like a spreadsheet does.
        let line = i + 2;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                errors.push(CsvRowError {
                    line,
                    message: e.to_string(),
                });
                continue;
            }
        };
        let get = |idx: Option<usize>| -> Option<String> {
            idx.and_then(|n| record.get(n))
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };

        let mut row = AssetCsvRow {
            line,
            asset_tag: get(cols.asset_tag),
            serial_number: get(cols.serial_number),
            make: get(cols.make),
            model: get(cols.model),
            location: get(cols.location),
            funding_source: get(cols.funding_source),
            purchase_date: get(cols.purchase_date),
            warranty_expires: get(cols.warranty_expires),
            notes: get(cols.notes),
            ..Default::default()
        };

        // A bad enum names the row and the value. Skipping silently would let a
        // typo quietly leave a hundred devices unchanged.
        if let Some(raw) = get(cols.asset_type) {
            match AssetType::parse(&raw) {
                Ok(v) => row.asset_type = Some(v),
                Err(_) => {
                    errors.push(CsvRowError {
                        line,
                        message: format!("{raw:?} is not a device type"),
                    });
                    continue;
                }
            }
        }
        if let Some(raw) = get(cols.status) {
            match AssetStatus::parse(&raw) {
                Ok(v) => row.status = Some(v),
                Err(_) => {
                    errors.push(CsvRowError {
                        line,
                        message: format!("{raw:?} is not a device status"),
                    });
                    continue;
                }
            }
        }

        if row.match_key().is_none() {
            errors.push(CsvRowError {
                line,
                message: "no serial number or asset tag, so this row cannot be \
                          matched to a device"
                    .into(),
            });
            continue;
        }

        rows.push(row);
    }

    (rows, errors)
}

struct ImportColumns {
    asset_tag: Option<usize>,
    serial_number: Option<usize>,
    asset_type: Option<usize>,
    make: Option<usize>,
    model: Option<usize>,
    status: Option<usize>,
    location: Option<usize>,
    funding_source: Option<usize>,
    purchase_date: Option<usize>,
    warranty_expires: Option<usize>,
    notes: Option<usize>,
}

#[cfg(test)]
mod tests;
