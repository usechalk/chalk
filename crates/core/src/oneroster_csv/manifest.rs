//! OneRoster 1.1 manifest.csv parsing.
//!
//! The manifest file lists which CSV files are present in a bulk data export
//! and whether they use `bulk` or `delta` processing mode.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{ChalkError, Result};

/// Processing mode for a file listed in the manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessingMode {
    Bulk,
    Delta,
    Absent,
}

/// A parsed manifest.csv entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    #[serde(rename = "propertyName")]
    pub property_name: String,
    pub value: String,
}

/// Parsed manifest with convenient file lookup.
#[derive(Debug, Default)]
pub struct Manifest {
    /// Map of filename (e.g. "orgs.csv") to processing mode.
    pub files: HashMap<String, ProcessingMode>,
    /// OneRoster manifest version if present.
    pub manifest_version: Option<String>,
    /// OneRoster version if present.
    pub oneroster_version: Option<String>,
}

impl Manifest {
    /// Parse a manifest.csv file from the given directory.
    pub fn from_dir(dir: &Path) -> Result<Self> {
        let manifest_path = dir.join("manifest.csv");
        if !manifest_path.exists() {
            return Ok(Self::default());
        }

        let mut rdr = csv::Reader::from_path(&manifest_path)
            .map_err(|e| ChalkError::Io(std::io::Error::other(e)))?;

        let mut manifest = Manifest::default();

        for result in rdr.deserialize() {
            let entry: ManifestEntry = result
                .map_err(|e| ChalkError::Serialization(format!("manifest.csv parse error: {e}")))?;

            match entry.property_name.as_str() {
                "manifest.version" => {
                    manifest.manifest_version = Some(entry.value);
                }
                "oneroster.version" => {
                    manifest.oneroster_version = Some(entry.value);
                }
                name if name.starts_with("file.") => {
                    // e.g. "file.orgs" -> "orgs.csv"
                    let file_key = name.strip_prefix("file.").unwrap_or(name);
                    let filename = format!("{file_key}.csv");
                    let mode = match entry.value.to_lowercase().as_str() {
                        "bulk" => ProcessingMode::Bulk,
                        "delta" => ProcessingMode::Delta,
                        _ => ProcessingMode::Absent,
                    };
                    manifest.files.insert(filename, mode);
                }
                _ => {} // ignore unknown properties
            }
        }

        Ok(manifest)
    }

    /// Check if a given CSV file is present and in bulk or delta mode.
    pub fn is_file_present(&self, filename: &str) -> bool {
        matches!(
            self.files.get(filename),
            Some(ProcessingMode::Bulk) | Some(ProcessingMode::Delta)
        )
    }

    /// Write a manifest.csv file to the given directory.
    pub fn write_to_dir(dir: &Path, files: &[&str]) -> Result<()> {
        let manifest_path = dir.join("manifest.csv");
        let mut wtr = csv::Writer::from_path(&manifest_path)
            .map_err(|e| ChalkError::Io(std::io::Error::other(e)))?;

        wtr.serialize(ManifestEntry {
            property_name: "manifest.version".to_string(),
            value: "1.0".to_string(),
        })
        .map_err(|e| ChalkError::Serialization(format!("manifest write error: {e}")))?;

        wtr.serialize(ManifestEntry {
            property_name: "oneroster.version".to_string(),
            value: "1.1".to_string(),
        })
        .map_err(|e| ChalkError::Serialization(format!("manifest write error: {e}")))?;

        for file in files {
            let name = file.strip_suffix(".csv").unwrap_or(file);
            wtr.serialize(ManifestEntry {
                property_name: format!("file.{name}"),
                value: "bulk".to_string(),
            })
            .map_err(|e| ChalkError::Serialization(format!("manifest write error: {e}")))?;
        }

        wtr.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn test_manifest_missing_file_returns_default() {
        let dir = create_temp_dir();
        let manifest = Manifest::from_dir(dir.path()).unwrap();
        assert!(manifest.files.is_empty());
        assert!(manifest.manifest_version.is_none());
    }

    #[test]
    fn test_manifest_round_trip() {
        let dir = create_temp_dir();
        let files = vec![
            "orgs.csv",
            "users.csv",
            "courses.csv",
            "classes.csv",
            "enrollments.csv",
            "academicSessions.csv",
            "demographics.csv",
        ];
        Manifest::write_to_dir(dir.path(), &files).unwrap();

        let manifest = Manifest::from_dir(dir.path()).unwrap();
        assert_eq!(manifest.manifest_version, Some("1.0".to_string()));
        assert_eq!(manifest.oneroster_version, Some("1.1".to_string()));
        assert!(manifest.is_file_present("orgs.csv"));
        assert!(manifest.is_file_present("users.csv"));
        assert!(manifest.is_file_present("courses.csv"));
        assert!(manifest.is_file_present("classes.csv"));
        assert!(manifest.is_file_present("enrollments.csv"));
        assert!(manifest.is_file_present("academicSessions.csv"));
        assert!(manifest.is_file_present("demographics.csv"));
        assert!(!manifest.is_file_present("nonexistent.csv"));
    }

    #[test]
    fn test_manifest_custom_content() {
        let dir = create_temp_dir();
        let content = "propertyName,value\nmanifest.version,1.0\noneroster.version,1.1\nfile.orgs,bulk\nfile.users,delta\nfile.classes,absent\n";
        fs::write(dir.path().join("manifest.csv"), content).unwrap();

        let manifest = Manifest::from_dir(dir.path()).unwrap();
        assert_eq!(manifest.files.get("orgs.csv"), Some(&ProcessingMode::Bulk));
        assert_eq!(
            manifest.files.get("users.csv"),
            Some(&ProcessingMode::Delta)
        );
        assert_eq!(
            manifest.files.get("classes.csv"),
            Some(&ProcessingMode::Absent)
        );
        assert!(manifest.is_file_present("orgs.csv"));
        assert!(manifest.is_file_present("users.csv"));
        assert!(!manifest.is_file_present("classes.csv")); // absent
    }

    #[test]
    fn test_manifest_is_file_present() {
        let mut manifest = Manifest::default();
        manifest
            .files
            .insert("orgs.csv".to_string(), ProcessingMode::Bulk);
        manifest
            .files
            .insert("users.csv".to_string(), ProcessingMode::Delta);
        manifest
            .files
            .insert("classes.csv".to_string(), ProcessingMode::Absent);

        assert!(manifest.is_file_present("orgs.csv"));
        assert!(manifest.is_file_present("users.csv"));
        assert!(!manifest.is_file_present("classes.csv"));
        assert!(!manifest.is_file_present("nonexistent.csv"));
    }
}
