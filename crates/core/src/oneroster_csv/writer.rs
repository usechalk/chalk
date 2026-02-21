//! OneRoster CSV writer — exports a `SyncPayload` to a directory of CSV files.

use std::path::Path;

use crate::connectors::SyncPayload;
use crate::error::{ChalkError, Result};

use super::manifest::Manifest;
use super::rows::{
    AcademicSessionCsvRow, ClassCsvRow, CourseCsvRow, DemographicsCsvRow, EnrollmentCsvRow,
    OrgCsvRow, UserCsvRow,
};

/// Write a complete OneRoster CSV export to the given directory.
///
/// Creates individual CSV files for each entity type present in the payload,
/// plus a manifest.csv listing all files.
pub fn write_oneroster_csv(payload: &SyncPayload, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;

    let mut files_written: Vec<&str> = Vec::new();

    if !payload.orgs.is_empty() {
        write_csv(
            &dir.join("orgs.csv"),
            payload.orgs.iter().map(OrgCsvRow::from_model),
        )?;
        files_written.push("orgs.csv");
    }

    if !payload.academic_sessions.is_empty() {
        write_csv(
            &dir.join("academicSessions.csv"),
            payload
                .academic_sessions
                .iter()
                .map(AcademicSessionCsvRow::from_model),
        )?;
        files_written.push("academicSessions.csv");
    }

    if !payload.users.is_empty() {
        write_csv(
            &dir.join("users.csv"),
            payload.users.iter().map(UserCsvRow::from_model),
        )?;
        files_written.push("users.csv");
    }

    if !payload.courses.is_empty() {
        write_csv(
            &dir.join("courses.csv"),
            payload.courses.iter().map(CourseCsvRow::from_model),
        )?;
        files_written.push("courses.csv");
    }

    if !payload.classes.is_empty() {
        write_csv(
            &dir.join("classes.csv"),
            payload.classes.iter().map(ClassCsvRow::from_model),
        )?;
        files_written.push("classes.csv");
    }

    if !payload.enrollments.is_empty() {
        write_csv(
            &dir.join("enrollments.csv"),
            payload.enrollments.iter().map(EnrollmentCsvRow::from_model),
        )?;
        files_written.push("enrollments.csv");
    }

    if !payload.demographics.is_empty() {
        write_csv(
            &dir.join("demographics.csv"),
            payload
                .demographics
                .iter()
                .map(DemographicsCsvRow::from_model),
        )?;
        files_written.push("demographics.csv");
    }

    Manifest::write_to_dir(dir, &files_written)?;

    Ok(())
}

fn write_csv<S: serde::Serialize>(path: &Path, rows: impl Iterator<Item = S>) -> Result<()> {
    let mut wtr =
        csv::Writer::from_path(path).map_err(|e| ChalkError::Io(std::io::Error::other(e)))?;

    for row in rows {
        wtr.serialize(row)
            .map_err(|e| ChalkError::Serialization(format!("CSV write error: {e}")))?;
    }

    wtr.flush()?;
    Ok(())
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
    use chrono::{NaiveDate, TimeZone, Utc};

    fn sample_datetime() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap()
    }

    fn sample_payload() -> SyncPayload {
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
    fn test_write_creates_all_files() {
        let dir = tempfile::tempdir().unwrap();
        let payload = sample_payload();
        write_oneroster_csv(&payload, dir.path()).unwrap();

        assert!(dir.path().join("manifest.csv").exists());
        assert!(dir.path().join("orgs.csv").exists());
        assert!(dir.path().join("users.csv").exists());
        assert!(dir.path().join("courses.csv").exists());
        assert!(dir.path().join("classes.csv").exists());
        assert!(dir.path().join("enrollments.csv").exists());
        assert!(dir.path().join("academicSessions.csv").exists());
        assert!(dir.path().join("demographics.csv").exists());
    }

    #[test]
    fn test_write_empty_payload_creates_only_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let payload = SyncPayload::default();
        write_oneroster_csv(&payload, dir.path()).unwrap();

        assert!(dir.path().join("manifest.csv").exists());
        assert!(!dir.path().join("orgs.csv").exists());
        assert!(!dir.path().join("users.csv").exists());
    }

    #[test]
    fn test_write_csv_has_headers() {
        let dir = tempfile::tempdir().unwrap();
        let payload = sample_payload();
        write_oneroster_csv(&payload, dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join("users.csv")).unwrap();
        let first_line = content.lines().next().unwrap();
        assert!(first_line.contains("sourcedId"));
        assert!(first_line.contains("username"));
        assert!(first_line.contains("givenName"));
        assert!(first_line.contains("familyName"));
    }
}
