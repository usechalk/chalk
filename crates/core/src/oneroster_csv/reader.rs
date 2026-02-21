//! OneRoster CSV reader — imports a directory of CSV files into a `SyncPayload`.

use std::path::Path;

use crate::connectors::SyncPayload;
use crate::error::{ChalkError, Result};

use super::manifest::Manifest;
use super::rows::{
    AcademicSessionCsvRow, ClassCsvRow, CourseCsvRow, DemographicsCsvRow, EnrollmentCsvRow,
    OrgCsvRow, UserCsvRow,
};

/// Read a complete OneRoster CSV import from the given directory.
///
/// If a manifest.csv is present, only files listed as `bulk` or `delta` are
/// read. If no manifest is present, all recognized CSV files found in the
/// directory are read.
pub fn read_oneroster_csv(dir: &Path) -> Result<SyncPayload> {
    if !dir.is_dir() {
        return Err(ChalkError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("directory not found: {}", dir.display()),
        )));
    }

    let manifest = Manifest::from_dir(dir)?;
    let has_manifest = !manifest.files.is_empty();

    let mut payload = SyncPayload::default();

    if should_read("orgs.csv", has_manifest, &manifest, dir) {
        payload.orgs = read_csv::<OrgCsvRow>(&dir.join("orgs.csv"))?
            .into_iter()
            .map(|row| row.to_model())
            .collect::<Result<Vec<_>>>()?;
    }

    if should_read("academicSessions.csv", has_manifest, &manifest, dir) {
        payload.academic_sessions =
            read_csv::<AcademicSessionCsvRow>(&dir.join("academicSessions.csv"))?
                .into_iter()
                .map(|row| row.to_model())
                .collect::<Result<Vec<_>>>()?;
    }

    if should_read("users.csv", has_manifest, &manifest, dir) {
        payload.users = read_csv::<UserCsvRow>(&dir.join("users.csv"))?
            .into_iter()
            .map(|row| row.to_model())
            .collect::<Result<Vec<_>>>()?;
    }

    if should_read("courses.csv", has_manifest, &manifest, dir) {
        payload.courses = read_csv::<CourseCsvRow>(&dir.join("courses.csv"))?
            .into_iter()
            .map(|row| row.to_model())
            .collect::<Result<Vec<_>>>()?;
    }

    if should_read("classes.csv", has_manifest, &manifest, dir) {
        payload.classes = read_csv::<ClassCsvRow>(&dir.join("classes.csv"))?
            .into_iter()
            .map(|row| row.to_model())
            .collect::<Result<Vec<_>>>()?;
    }

    if should_read("enrollments.csv", has_manifest, &manifest, dir) {
        payload.enrollments = read_csv::<EnrollmentCsvRow>(&dir.join("enrollments.csv"))?
            .into_iter()
            .map(|row| row.to_model())
            .collect::<Result<Vec<_>>>()?;
    }

    if should_read("demographics.csv", has_manifest, &manifest, dir) {
        payload.demographics = read_csv::<DemographicsCsvRow>(&dir.join("demographics.csv"))?
            .into_iter()
            .map(|row| row.to_model())
            .collect::<Result<Vec<_>>>()?;
    }

    Ok(payload)
}

fn should_read(filename: &str, has_manifest: bool, manifest: &Manifest, dir: &Path) -> bool {
    if has_manifest {
        manifest.is_file_present(filename)
    } else {
        dir.join(filename).exists()
    }
}

fn read_csv<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let mut rdr =
        csv::Reader::from_path(path).map_err(|e| ChalkError::Io(std::io::Error::other(e)))?;

    let mut rows = Vec::new();
    for result in rdr.deserialize() {
        let row: T = result.map_err(|e| {
            ChalkError::Serialization(format!("CSV parse error in {}: {e}", path.display()))
        })?;
        rows.push(row);
    }

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        academic_session::AcademicSession,
        class::Class,
        common::*,
        course::Course,
        demographics::Demographics,
        enrollment::Enrollment,
        org::Org,
        user::{User, UserIdentifier},
    };
    use crate::oneroster_csv::writer::write_oneroster_csv;
    use chrono::{NaiveDate, TimeZone, Utc};

    fn sample_datetime() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap()
    }

    fn full_payload() -> SyncPayload {
        SyncPayload {
            orgs: vec![Org {
                sourced_id: "org-001".to_string(),
                status: Status::Active,
                date_last_modified: sample_datetime(),
                metadata: None,
                name: "Springfield District".to_string(),
                org_type: OrgType::District,
                identifier: Some("SSD001".to_string()),
                parent: None,
                children: vec!["org-002".to_string()],
            }],
            academic_sessions: vec![AcademicSession {
                sourced_id: "term-001".to_string(),
                status: Status::Active,
                date_last_modified: sample_datetime(),
                metadata: None,
                title: "Fall 2025".to_string(),
                start_date: NaiveDate::from_ymd_opt(2025, 8, 15).unwrap(),
                end_date: NaiveDate::from_ymd_opt(2025, 12, 20).unwrap(),
                session_type: SessionType::Term,
                parent: None,
                school_year: "2025".to_string(),
                children: vec![],
            }],
            users: vec![User {
                sourced_id: "user-001".to_string(),
                status: Status::Active,
                date_last_modified: sample_datetime(),
                metadata: None,
                username: "jdoe".to_string(),
                user_ids: vec![UserIdentifier {
                    type_: "LDAP".to_string(),
                    identifier: "jdoe@example.com".to_string(),
                }],
                enabled_user: true,
                given_name: "John".to_string(),
                family_name: "Doe".to_string(),
                middle_name: Some("M".to_string()),
                role: RoleType::Student,
                identifier: Some("STU001".to_string()),
                email: Some("jdoe@example.com".to_string()),
                sms: None,
                phone: None,
                agents: vec!["parent-001".to_string()],
                orgs: vec!["org-001".to_string()],
                grades: vec!["09".to_string()],
            }],
            courses: vec![Course {
                sourced_id: "course-001".to_string(),
                status: Status::Active,
                date_last_modified: sample_datetime(),
                metadata: None,
                title: "Algebra I".to_string(),
                school_year: Some("2025".to_string()),
                course_code: Some("ALG1".to_string()),
                grades: vec!["09".to_string()],
                subjects: vec!["Mathematics".to_string()],
                org: "org-001".to_string(),
            }],
            classes: vec![Class {
                sourced_id: "class-001".to_string(),
                status: Status::Active,
                date_last_modified: sample_datetime(),
                metadata: None,
                title: "Algebra I - Period 1".to_string(),
                class_code: Some("ALG1-P1".to_string()),
                class_type: ClassType::Scheduled,
                location: Some("Room 101".to_string()),
                grades: vec!["09".to_string()],
                subjects: vec!["Mathematics".to_string()],
                course: "course-001".to_string(),
                school: "org-002".to_string(),
                terms: vec!["term-001".to_string()],
                periods: vec!["1".to_string()],
            }],
            enrollments: vec![Enrollment {
                sourced_id: "enr-001".to_string(),
                status: Status::Active,
                date_last_modified: sample_datetime(),
                metadata: None,
                user: "user-001".to_string(),
                class: "class-001".to_string(),
                school: "org-002".to_string(),
                role: EnrollmentRole::Student,
                primary: Some(true),
                begin_date: Some(NaiveDate::from_ymd_opt(2025, 8, 15).unwrap()),
                end_date: Some(NaiveDate::from_ymd_opt(2026, 6, 1).unwrap()),
            }],
            demographics: vec![Demographics {
                sourced_id: "user-001".to_string(),
                status: Status::Active,
                date_last_modified: sample_datetime(),
                metadata: None,
                birth_date: Some(NaiveDate::from_ymd_opt(2009, 3, 15).unwrap()),
                sex: Some(Sex::Male),
                american_indian_or_alaska_native: Some(false),
                asian: Some(false),
                black_or_african_american: Some(false),
                native_hawaiian_or_other_pacific_islander: Some(false),
                white: Some(true),
                demographic_race_two_or_more_races: Some(false),
                hispanic_or_latino_ethnicity: Some(false),
                country_of_birth_code: Some("US".to_string()),
                state_of_birth_abbreviation: Some("IL".to_string()),
                city_of_birth: Some("Springfield".to_string()),
                public_school_residence_status: None,
            }],
        }
    }

    #[test]
    fn test_full_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let original = full_payload();
        write_oneroster_csv(&original, dir.path()).unwrap();
        let loaded = read_oneroster_csv(dir.path()).unwrap();

        assert_eq!(loaded.orgs, original.orgs);
        assert_eq!(loaded.academic_sessions, original.academic_sessions);
        assert_eq!(loaded.users, original.users);
        assert_eq!(loaded.courses, original.courses);
        assert_eq!(loaded.classes, original.classes);
        assert_eq!(loaded.enrollments, original.enrollments);
        assert_eq!(loaded.demographics, original.demographics);
    }

    #[test]
    fn test_read_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let payload = read_oneroster_csv(dir.path()).unwrap();
        assert!(payload.orgs.is_empty());
        assert!(payload.users.is_empty());
        assert!(payload.courses.is_empty());
        assert!(payload.classes.is_empty());
        assert!(payload.enrollments.is_empty());
        assert!(payload.academic_sessions.is_empty());
        assert!(payload.demographics.is_empty());
    }

    #[test]
    fn test_read_nonexistent_dir() {
        let result = read_oneroster_csv(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_partial_export() {
        let dir = tempfile::tempdir().unwrap();
        let payload = SyncPayload {
            orgs: full_payload().orgs,
            users: full_payload().users,
            ..Default::default()
        };
        write_oneroster_csv(&payload, dir.path()).unwrap();

        let loaded = read_oneroster_csv(dir.path()).unwrap();
        assert_eq!(loaded.orgs.len(), 1);
        assert_eq!(loaded.users.len(), 1);
        assert!(loaded.courses.is_empty());
        assert!(loaded.classes.is_empty());
        assert!(loaded.enrollments.is_empty());
    }

    #[test]
    fn test_round_trip_multiple_records() {
        let dir = tempfile::tempdir().unwrap();
        let mut payload = full_payload();
        payload.users.push(User {
            sourced_id: "user-002".to_string(),
            status: Status::ToBeDeleted,
            date_last_modified: sample_datetime(),
            metadata: None,
            username: "asmith".to_string(),
            user_ids: vec![],
            enabled_user: false,
            given_name: "Alice".to_string(),
            family_name: "Smith".to_string(),
            middle_name: None,
            role: RoleType::Teacher,
            identifier: None,
            email: None,
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string(), "org-002".to_string()],
            grades: vec![],
        });

        write_oneroster_csv(&payload, dir.path()).unwrap();
        let loaded = read_oneroster_csv(dir.path()).unwrap();
        assert_eq!(loaded.users.len(), 2);
        assert_eq!(loaded.users[1].sourced_id, "user-002");
        assert_eq!(loaded.users[1].status, Status::ToBeDeleted);
        assert!(loaded.users[1].middle_name.is_none());
        assert!(loaded.users[1].email.is_none());
        assert_eq!(loaded.users[1].orgs.len(), 2);
    }

    #[test]
    fn test_round_trip_without_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let original = full_payload();
        write_oneroster_csv(&original, dir.path()).unwrap();

        // Remove manifest to test fallback behavior
        std::fs::remove_file(dir.path().join("manifest.csv")).unwrap();

        let loaded = read_oneroster_csv(dir.path()).unwrap();
        assert_eq!(loaded.orgs, original.orgs);
        assert_eq!(loaded.users, original.users);
    }
}
