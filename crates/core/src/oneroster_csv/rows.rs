//! Intermediate CSV row structs for OneRoster 1.1 CSV format.
//!
//! These structs match the exact CSV column names from the OneRoster 1.1
//! specification and handle conversion to/from the domain model types.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{ChalkError, Result};
use crate::models::{
    academic_session::AcademicSession,
    class::Class,
    common::{ClassType, EnrollmentRole, OrgType, RoleType, SessionType, Sex, Status},
    course::Course,
    demographics::Demographics,
    enrollment::Enrollment,
    org::Org,
    user::{User, UserIdentifier},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn vec_to_csv(items: &[String]) -> String {
    items.join(",")
}

fn csv_to_vec(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(',').map(|v| v.trim().to_string()).collect()
    }
}

fn bool_to_csv(b: bool) -> String {
    if b {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

fn csv_to_bool(s: &str) -> bool {
    s.eq_ignore_ascii_case("true")
}

fn opt_bool_to_csv(b: &Option<bool>) -> String {
    match b {
        Some(v) => bool_to_csv(*v),
        None => String::new(),
    }
}

fn csv_to_opt_bool(s: &str) -> Option<bool> {
    if s.is_empty() {
        None
    } else {
        Some(csv_to_bool(s))
    }
}

fn datetime_to_csv(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

fn csv_to_datetime(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| ChalkError::Serialization(format!("invalid datetime '{s}': {e}")))
}

fn date_to_csv(d: &NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

fn csv_to_date(s: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|e| ChalkError::Serialization(format!("invalid date '{s}': {e}")))
}

fn opt_date_to_csv(d: &Option<NaiveDate>) -> String {
    match d {
        Some(d) => date_to_csv(d),
        None => String::new(),
    }
}

fn csv_to_opt_date(s: &str) -> Result<Option<NaiveDate>> {
    if s.is_empty() {
        Ok(None)
    } else {
        csv_to_date(s).map(Some)
    }
}

fn status_to_csv(s: &Status) -> String {
    match s {
        Status::Active => "active".to_string(),
        Status::ToBeDeleted => "tobedeleted".to_string(),
    }
}

fn csv_to_status(s: &str) -> Result<Status> {
    match s.to_lowercase().as_str() {
        "active" => Ok(Status::Active),
        "tobedeleted" => Ok(Status::ToBeDeleted),
        _ => Err(ChalkError::Serialization(format!("unknown status: {s}"))),
    }
}

fn user_ids_to_csv(ids: &[UserIdentifier]) -> String {
    ids.iter()
        .map(|uid| format!("{}:{}", uid.type_, uid.identifier))
        .collect::<Vec<_>>()
        .join("|")
}

fn csv_to_user_ids(s: &str) -> Vec<UserIdentifier> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('|')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, ':');
            let type_ = parts.next()?.to_string();
            let identifier = parts.next()?.to_string();
            Some(UserIdentifier { type_, identifier })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// OrgCsvRow
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct OrgCsvRow {
    #[serde(rename = "sourcedId")]
    pub sourced_id: String,
    pub status: String,
    #[serde(rename = "dateLastModified")]
    pub date_last_modified: String,
    pub name: String,
    #[serde(rename = "type")]
    pub org_type: String,
    pub identifier: String,
    pub parent: String,
    pub children: String,
}

impl OrgCsvRow {
    pub fn from_model(org: &Org) -> Self {
        Self {
            sourced_id: org.sourced_id.clone(),
            status: status_to_csv(&org.status),
            date_last_modified: datetime_to_csv(&org.date_last_modified),
            name: org.name.clone(),
            org_type: serde_json::to_value(&org.org_type)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            identifier: org.identifier.clone().unwrap_or_default(),
            parent: org.parent.clone().unwrap_or_default(),
            children: vec_to_csv(&org.children),
        }
    }

    pub fn to_model(&self) -> Result<Org> {
        let org_type: OrgType =
            serde_json::from_value(serde_json::Value::String(self.org_type.clone())).map_err(
                |e| ChalkError::Serialization(format!("invalid org type '{}': {e}", self.org_type)),
            )?;

        Ok(Org {
            sourced_id: self.sourced_id.clone(),
            status: csv_to_status(&self.status)?,
            date_last_modified: csv_to_datetime(&self.date_last_modified)?,
            metadata: None,
            name: self.name.clone(),
            org_type,
            identifier: if self.identifier.is_empty() {
                None
            } else {
                Some(self.identifier.clone())
            },
            parent: if self.parent.is_empty() {
                None
            } else {
                Some(self.parent.clone())
            },
            children: csv_to_vec(&self.children),
        })
    }
}

// ---------------------------------------------------------------------------
// AcademicSessionCsvRow
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct AcademicSessionCsvRow {
    #[serde(rename = "sourcedId")]
    pub sourced_id: String,
    pub status: String,
    #[serde(rename = "dateLastModified")]
    pub date_last_modified: String,
    pub title: String,
    #[serde(rename = "startDate")]
    pub start_date: String,
    #[serde(rename = "endDate")]
    pub end_date: String,
    #[serde(rename = "type")]
    pub session_type: String,
    pub parent: String,
    #[serde(rename = "schoolYear")]
    pub school_year: String,
    pub children: String,
}

impl AcademicSessionCsvRow {
    pub fn from_model(session: &AcademicSession) -> Self {
        Self {
            sourced_id: session.sourced_id.clone(),
            status: status_to_csv(&session.status),
            date_last_modified: datetime_to_csv(&session.date_last_modified),
            title: session.title.clone(),
            start_date: date_to_csv(&session.start_date),
            end_date: date_to_csv(&session.end_date),
            session_type: serde_json::to_value(&session.session_type)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            parent: session.parent.clone().unwrap_or_default(),
            school_year: session.school_year.clone(),
            children: vec_to_csv(&session.children),
        }
    }

    pub fn to_model(&self) -> Result<AcademicSession> {
        let session_type: SessionType = serde_json::from_value(serde_json::Value::String(
            self.session_type.clone(),
        ))
        .map_err(|e| {
            ChalkError::Serialization(format!("invalid session type '{}': {e}", self.session_type))
        })?;

        Ok(AcademicSession {
            sourced_id: self.sourced_id.clone(),
            status: csv_to_status(&self.status)?,
            date_last_modified: csv_to_datetime(&self.date_last_modified)?,
            metadata: None,
            title: self.title.clone(),
            start_date: csv_to_date(&self.start_date)?,
            end_date: csv_to_date(&self.end_date)?,
            session_type,
            parent: if self.parent.is_empty() {
                None
            } else {
                Some(self.parent.clone())
            },
            school_year: self.school_year.clone(),
            children: csv_to_vec(&self.children),
        })
    }
}

// ---------------------------------------------------------------------------
// UserCsvRow
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct UserCsvRow {
    #[serde(rename = "sourcedId")]
    pub sourced_id: String,
    pub status: String,
    #[serde(rename = "dateLastModified")]
    pub date_last_modified: String,
    pub username: String,
    #[serde(rename = "userIds")]
    pub user_ids: String,
    #[serde(rename = "enabledUser")]
    pub enabled_user: String,
    #[serde(rename = "givenName")]
    pub given_name: String,
    #[serde(rename = "familyName")]
    pub family_name: String,
    #[serde(rename = "middleName")]
    pub middle_name: String,
    pub role: String,
    pub identifier: String,
    pub email: String,
    pub sms: String,
    pub phone: String,
    pub agents: String,
    pub orgs: String,
    pub grades: String,
}

impl UserCsvRow {
    pub fn from_model(user: &User) -> Self {
        Self {
            sourced_id: user.sourced_id.clone(),
            status: status_to_csv(&user.status),
            date_last_modified: datetime_to_csv(&user.date_last_modified),
            username: user.username.clone(),
            user_ids: user_ids_to_csv(&user.user_ids),
            enabled_user: bool_to_csv(user.enabled_user),
            given_name: user.given_name.clone(),
            family_name: user.family_name.clone(),
            middle_name: user.middle_name.clone().unwrap_or_default(),
            role: serde_json::to_value(&user.role)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            identifier: user.identifier.clone().unwrap_or_default(),
            email: user.email.clone().unwrap_or_default(),
            sms: user.sms.clone().unwrap_or_default(),
            phone: user.phone.clone().unwrap_or_default(),
            agents: vec_to_csv(&user.agents),
            orgs: vec_to_csv(&user.orgs),
            grades: vec_to_csv(&user.grades),
        }
    }

    pub fn to_model(&self) -> Result<User> {
        let role: RoleType = serde_json::from_value(serde_json::Value::String(self.role.clone()))
            .map_err(|e| {
            ChalkError::Serialization(format!("invalid role '{}': {e}", self.role))
        })?;

        Ok(User {
            sourced_id: self.sourced_id.clone(),
            status: csv_to_status(&self.status)?,
            date_last_modified: csv_to_datetime(&self.date_last_modified)?,
            metadata: None,
            username: self.username.clone(),
            user_ids: csv_to_user_ids(&self.user_ids),
            enabled_user: csv_to_bool(&self.enabled_user),
            given_name: self.given_name.clone(),
            family_name: self.family_name.clone(),
            middle_name: if self.middle_name.is_empty() {
                None
            } else {
                Some(self.middle_name.clone())
            },
            role,
            identifier: if self.identifier.is_empty() {
                None
            } else {
                Some(self.identifier.clone())
            },
            email: if self.email.is_empty() {
                None
            } else {
                Some(self.email.clone())
            },
            sms: if self.sms.is_empty() {
                None
            } else {
                Some(self.sms.clone())
            },
            phone: if self.phone.is_empty() {
                None
            } else {
                Some(self.phone.clone())
            },
            agents: csv_to_vec(&self.agents),
            orgs: csv_to_vec(&self.orgs),
            grades: csv_to_vec(&self.grades),
        })
    }
}

// ---------------------------------------------------------------------------
// CourseCsvRow
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CourseCsvRow {
    #[serde(rename = "sourcedId")]
    pub sourced_id: String,
    pub status: String,
    #[serde(rename = "dateLastModified")]
    pub date_last_modified: String,
    pub title: String,
    #[serde(rename = "schoolYear")]
    pub school_year: String,
    #[serde(rename = "courseCode")]
    pub course_code: String,
    pub grades: String,
    pub subjects: String,
    pub org: String,
}

impl CourseCsvRow {
    pub fn from_model(course: &Course) -> Self {
        Self {
            sourced_id: course.sourced_id.clone(),
            status: status_to_csv(&course.status),
            date_last_modified: datetime_to_csv(&course.date_last_modified),
            title: course.title.clone(),
            school_year: course.school_year.clone().unwrap_or_default(),
            course_code: course.course_code.clone().unwrap_or_default(),
            grades: vec_to_csv(&course.grades),
            subjects: vec_to_csv(&course.subjects),
            org: course.org.clone(),
        }
    }

    pub fn to_model(&self) -> Result<Course> {
        Ok(Course {
            sourced_id: self.sourced_id.clone(),
            status: csv_to_status(&self.status)?,
            date_last_modified: csv_to_datetime(&self.date_last_modified)?,
            metadata: None,
            title: self.title.clone(),
            school_year: if self.school_year.is_empty() {
                None
            } else {
                Some(self.school_year.clone())
            },
            course_code: if self.course_code.is_empty() {
                None
            } else {
                Some(self.course_code.clone())
            },
            grades: csv_to_vec(&self.grades),
            subjects: csv_to_vec(&self.subjects),
            org: self.org.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// ClassCsvRow
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassCsvRow {
    #[serde(rename = "sourcedId")]
    pub sourced_id: String,
    pub status: String,
    #[serde(rename = "dateLastModified")]
    pub date_last_modified: String,
    pub title: String,
    #[serde(rename = "classCode")]
    pub class_code: String,
    #[serde(rename = "classType")]
    pub class_type: String,
    pub location: String,
    pub grades: String,
    pub subjects: String,
    pub course: String,
    pub school: String,
    pub terms: String,
    pub periods: String,
}

impl ClassCsvRow {
    pub fn from_model(class: &Class) -> Self {
        Self {
            sourced_id: class.sourced_id.clone(),
            status: status_to_csv(&class.status),
            date_last_modified: datetime_to_csv(&class.date_last_modified),
            title: class.title.clone(),
            class_code: class.class_code.clone().unwrap_or_default(),
            class_type: serde_json::to_value(&class.class_type)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            location: class.location.clone().unwrap_or_default(),
            grades: vec_to_csv(&class.grades),
            subjects: vec_to_csv(&class.subjects),
            course: class.course.clone(),
            school: class.school.clone(),
            terms: vec_to_csv(&class.terms),
            periods: vec_to_csv(&class.periods),
        }
    }

    pub fn to_model(&self) -> Result<Class> {
        let class_type: ClassType = serde_json::from_value(serde_json::Value::String(
            self.class_type.clone(),
        ))
        .map_err(|e| {
            ChalkError::Serialization(format!("invalid class type '{}': {e}", self.class_type))
        })?;

        Ok(Class {
            sourced_id: self.sourced_id.clone(),
            status: csv_to_status(&self.status)?,
            date_last_modified: csv_to_datetime(&self.date_last_modified)?,
            metadata: None,
            title: self.title.clone(),
            class_code: if self.class_code.is_empty() {
                None
            } else {
                Some(self.class_code.clone())
            },
            class_type,
            location: if self.location.is_empty() {
                None
            } else {
                Some(self.location.clone())
            },
            grades: csv_to_vec(&self.grades),
            subjects: csv_to_vec(&self.subjects),
            course: self.course.clone(),
            school: self.school.clone(),
            terms: csv_to_vec(&self.terms),
            periods: csv_to_vec(&self.periods),
        })
    }
}

// ---------------------------------------------------------------------------
// EnrollmentCsvRow
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentCsvRow {
    #[serde(rename = "sourcedId")]
    pub sourced_id: String,
    pub status: String,
    #[serde(rename = "dateLastModified")]
    pub date_last_modified: String,
    pub user: String,
    pub class: String,
    pub school: String,
    pub role: String,
    pub primary: String,
    #[serde(rename = "beginDate")]
    pub begin_date: String,
    #[serde(rename = "endDate")]
    pub end_date: String,
}

impl EnrollmentCsvRow {
    pub fn from_model(enrollment: &Enrollment) -> Self {
        Self {
            sourced_id: enrollment.sourced_id.clone(),
            status: status_to_csv(&enrollment.status),
            date_last_modified: datetime_to_csv(&enrollment.date_last_modified),
            user: enrollment.user.clone(),
            class: enrollment.class.clone(),
            school: enrollment.school.clone(),
            role: serde_json::to_value(&enrollment.role)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            primary: opt_bool_to_csv(&enrollment.primary),
            begin_date: opt_date_to_csv(&enrollment.begin_date),
            end_date: opt_date_to_csv(&enrollment.end_date),
        }
    }

    pub fn to_model(&self) -> Result<Enrollment> {
        let role: EnrollmentRole =
            serde_json::from_value(serde_json::Value::String(self.role.clone())).map_err(|e| {
                ChalkError::Serialization(format!("invalid enrollment role '{}': {e}", self.role))
            })?;

        Ok(Enrollment {
            sourced_id: self.sourced_id.clone(),
            status: csv_to_status(&self.status)?,
            date_last_modified: csv_to_datetime(&self.date_last_modified)?,
            metadata: None,
            user: self.user.clone(),
            class: self.class.clone(),
            school: self.school.clone(),
            role,
            primary: csv_to_opt_bool(&self.primary),
            begin_date: csv_to_opt_date(&self.begin_date)?,
            end_date: csv_to_opt_date(&self.end_date)?,
        })
    }
}

// ---------------------------------------------------------------------------
// DemographicsCsvRow
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct DemographicsCsvRow {
    #[serde(rename = "sourcedId")]
    pub sourced_id: String,
    pub status: String,
    #[serde(rename = "dateLastModified")]
    pub date_last_modified: String,
    #[serde(rename = "birthDate")]
    pub birth_date: String,
    pub sex: String,
    #[serde(rename = "americanIndianOrAlaskaNative")]
    pub american_indian_or_alaska_native: String,
    pub asian: String,
    #[serde(rename = "blackOrAfricanAmerican")]
    pub black_or_african_american: String,
    #[serde(rename = "nativeHawaiianOrOtherPacificIslander")]
    pub native_hawaiian_or_other_pacific_islander: String,
    pub white: String,
    #[serde(rename = "demographicRaceTwoOrMoreRaces")]
    pub demographic_race_two_or_more_races: String,
    #[serde(rename = "hispanicOrLatinoEthnicity")]
    pub hispanic_or_latino_ethnicity: String,
    #[serde(rename = "countryOfBirthCode")]
    pub country_of_birth_code: String,
    #[serde(rename = "stateOfBirthAbbreviation")]
    pub state_of_birth_abbreviation: String,
    #[serde(rename = "cityOfBirth")]
    pub city_of_birth: String,
    #[serde(rename = "publicSchoolResidenceStatus")]
    pub public_school_residence_status: String,
}

impl DemographicsCsvRow {
    pub fn from_model(demo: &Demographics) -> Self {
        let sex_str = demo
            .sex
            .as_ref()
            .map(|s| {
                serde_json::to_value(s)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .unwrap_or_default();

        Self {
            sourced_id: demo.sourced_id.clone(),
            status: status_to_csv(&demo.status),
            date_last_modified: datetime_to_csv(&demo.date_last_modified),
            birth_date: opt_date_to_csv(&demo.birth_date),
            sex: sex_str,
            american_indian_or_alaska_native: opt_bool_to_csv(
                &demo.american_indian_or_alaska_native,
            ),
            asian: opt_bool_to_csv(&demo.asian),
            black_or_african_american: opt_bool_to_csv(&demo.black_or_african_american),
            native_hawaiian_or_other_pacific_islander: opt_bool_to_csv(
                &demo.native_hawaiian_or_other_pacific_islander,
            ),
            white: opt_bool_to_csv(&demo.white),
            demographic_race_two_or_more_races: opt_bool_to_csv(
                &demo.demographic_race_two_or_more_races,
            ),
            hispanic_or_latino_ethnicity: opt_bool_to_csv(&demo.hispanic_or_latino_ethnicity),
            country_of_birth_code: demo.country_of_birth_code.clone().unwrap_or_default(),
            state_of_birth_abbreviation: demo
                .state_of_birth_abbreviation
                .clone()
                .unwrap_or_default(),
            city_of_birth: demo.city_of_birth.clone().unwrap_or_default(),
            public_school_residence_status: demo
                .public_school_residence_status
                .clone()
                .unwrap_or_default(),
        }
    }

    pub fn to_model(&self) -> Result<Demographics> {
        let sex = if self.sex.is_empty() {
            None
        } else {
            let s: Sex = serde_json::from_value(serde_json::Value::String(self.sex.clone()))
                .map_err(|e| {
                    ChalkError::Serialization(format!("invalid sex '{}': {e}", self.sex))
                })?;
            Some(s)
        };

        Ok(Demographics {
            sourced_id: self.sourced_id.clone(),
            status: csv_to_status(&self.status)?,
            date_last_modified: csv_to_datetime(&self.date_last_modified)?,
            metadata: None,
            birth_date: csv_to_opt_date(&self.birth_date)?,
            sex,
            american_indian_or_alaska_native: csv_to_opt_bool(
                &self.american_indian_or_alaska_native,
            ),
            asian: csv_to_opt_bool(&self.asian),
            black_or_african_american: csv_to_opt_bool(&self.black_or_african_american),
            native_hawaiian_or_other_pacific_islander: csv_to_opt_bool(
                &self.native_hawaiian_or_other_pacific_islander,
            ),
            white: csv_to_opt_bool(&self.white),
            demographic_race_two_or_more_races: csv_to_opt_bool(
                &self.demographic_race_two_or_more_races,
            ),
            hispanic_or_latino_ethnicity: csv_to_opt_bool(&self.hispanic_or_latino_ethnicity),
            country_of_birth_code: if self.country_of_birth_code.is_empty() {
                None
            } else {
                Some(self.country_of_birth_code.clone())
            },
            state_of_birth_abbreviation: if self.state_of_birth_abbreviation.is_empty() {
                None
            } else {
                Some(self.state_of_birth_abbreviation.clone())
            },
            city_of_birth: if self.city_of_birth.is_empty() {
                None
            } else {
                Some(self.city_of_birth.clone())
            },
            public_school_residence_status: if self.public_school_residence_status.is_empty() {
                None
            } else {
                Some(self.public_school_residence_status.clone())
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_datetime() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap()
    }

    // -- Helper tests --

    #[test]
    fn test_vec_to_csv_empty() {
        assert_eq!(vec_to_csv(&[]), "");
    }

    #[test]
    fn test_vec_to_csv_single() {
        assert_eq!(vec_to_csv(&["a".to_string()]), "a");
    }

    #[test]
    fn test_vec_to_csv_multiple() {
        assert_eq!(
            vec_to_csv(&["a".to_string(), "b".to_string(), "c".to_string()]),
            "a,b,c"
        );
    }

    #[test]
    fn test_csv_to_vec_empty() {
        assert!(csv_to_vec("").is_empty());
    }

    #[test]
    fn test_csv_to_vec_single() {
        assert_eq!(csv_to_vec("a"), vec!["a"]);
    }

    #[test]
    fn test_csv_to_vec_multiple() {
        assert_eq!(csv_to_vec("a,b,c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_csv_to_vec_trims_whitespace() {
        assert_eq!(csv_to_vec("a, b , c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_bool_round_trip() {
        assert_eq!(bool_to_csv(true), "true");
        assert_eq!(bool_to_csv(false), "false");
        assert!(csv_to_bool("true"));
        assert!(csv_to_bool("TRUE"));
        assert!(!csv_to_bool("false"));
        assert!(!csv_to_bool(""));
    }

    #[test]
    fn test_opt_bool_round_trip() {
        assert_eq!(opt_bool_to_csv(&Some(true)), "true");
        assert_eq!(opt_bool_to_csv(&Some(false)), "false");
        assert_eq!(opt_bool_to_csv(&None), "");
        assert_eq!(csv_to_opt_bool("true"), Some(true));
        assert_eq!(csv_to_opt_bool("false"), Some(false));
        assert_eq!(csv_to_opt_bool(""), None);
    }

    #[test]
    fn test_user_ids_round_trip() {
        let ids = vec![
            UserIdentifier {
                type_: "LDAP".to_string(),
                identifier: "jdoe@example.com".to_string(),
            },
            UserIdentifier {
                type_: "SIS".to_string(),
                identifier: "12345".to_string(),
            },
        ];
        let csv = user_ids_to_csv(&ids);
        assert_eq!(csv, "LDAP:jdoe@example.com|SIS:12345");
        let back = csv_to_user_ids(&csv);
        assert_eq!(back, ids);
    }

    #[test]
    fn test_user_ids_empty() {
        assert_eq!(user_ids_to_csv(&[]), "");
        assert!(csv_to_user_ids("").is_empty());
    }

    #[test]
    fn test_datetime_round_trip() {
        let dt = sample_datetime();
        let csv = datetime_to_csv(&dt);
        let back = csv_to_datetime(&csv).unwrap();
        assert_eq!(back, dt);
    }

    #[test]
    fn test_date_round_trip() {
        let d = NaiveDate::from_ymd_opt(2025, 8, 15).unwrap();
        let csv = date_to_csv(&d);
        assert_eq!(csv, "2025-08-15");
        let back = csv_to_date(&csv).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn test_opt_date_round_trip() {
        let d = Some(NaiveDate::from_ymd_opt(2025, 8, 15).unwrap());
        let csv = opt_date_to_csv(&d);
        let back = csv_to_opt_date(&csv).unwrap();
        assert_eq!(back, d);

        assert_eq!(opt_date_to_csv(&None), "");
        assert_eq!(csv_to_opt_date("").unwrap(), None);
    }

    #[test]
    fn test_status_round_trip() {
        assert_eq!(status_to_csv(&Status::Active), "active");
        assert_eq!(status_to_csv(&Status::ToBeDeleted), "tobedeleted");
        assert_eq!(csv_to_status("active").unwrap(), Status::Active);
        assert_eq!(csv_to_status("tobedeleted").unwrap(), Status::ToBeDeleted);
    }

    // -- OrgCsvRow round trip --

    #[test]
    fn test_org_csv_round_trip() {
        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: sample_datetime(),
            metadata: None,
            name: "Springfield District".to_string(),
            org_type: OrgType::District,
            identifier: Some("SSD001".to_string()),
            parent: None,
            children: vec!["org-002".to_string(), "org-003".to_string()],
        };
        let row = OrgCsvRow::from_model(&org);
        let back = row.to_model().unwrap();
        assert_eq!(back, org);
    }

    // -- UserCsvRow round trip --

    #[test]
    fn test_user_csv_round_trip() {
        let user = User {
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
        };
        let row = UserCsvRow::from_model(&user);
        let back = row.to_model().unwrap();
        assert_eq!(back, user);
    }

    // -- CourseCsvRow round trip --

    #[test]
    fn test_course_csv_round_trip() {
        let course = Course {
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
        };
        let row = CourseCsvRow::from_model(&course);
        let back = row.to_model().unwrap();
        assert_eq!(back, course);
    }

    // -- ClassCsvRow round trip --

    #[test]
    fn test_class_csv_round_trip() {
        let class = Class {
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
        };
        let row = ClassCsvRow::from_model(&class);
        let back = row.to_model().unwrap();
        assert_eq!(back, class);
    }

    // -- EnrollmentCsvRow round trip --

    #[test]
    fn test_enrollment_csv_round_trip() {
        let enrollment = Enrollment {
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
        };
        let row = EnrollmentCsvRow::from_model(&enrollment);
        let back = row.to_model().unwrap();
        assert_eq!(back, enrollment);
    }

    #[test]
    fn test_enrollment_csv_optional_fields() {
        let enrollment = Enrollment {
            sourced_id: "enr-002".to_string(),
            status: Status::Active,
            date_last_modified: sample_datetime(),
            metadata: None,
            user: "user-002".to_string(),
            class: "class-002".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Teacher,
            primary: None,
            begin_date: None,
            end_date: None,
        };
        let row = EnrollmentCsvRow::from_model(&enrollment);
        assert_eq!(row.primary, "");
        assert_eq!(row.begin_date, "");
        assert_eq!(row.end_date, "");
        let back = row.to_model().unwrap();
        assert_eq!(back, enrollment);
    }

    // -- DemographicsCsvRow round trip --

    #[test]
    fn test_demographics_csv_round_trip() {
        let demo = Demographics {
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
        };
        let row = DemographicsCsvRow::from_model(&demo);
        let back = row.to_model().unwrap();
        assert_eq!(back, demo);
    }

    #[test]
    fn test_demographics_csv_all_empty() {
        let demo = Demographics {
            sourced_id: "user-002".to_string(),
            status: Status::Active,
            date_last_modified: sample_datetime(),
            metadata: None,
            birth_date: None,
            sex: None,
            american_indian_or_alaska_native: None,
            asian: None,
            black_or_african_american: None,
            native_hawaiian_or_other_pacific_islander: None,
            white: None,
            demographic_race_two_or_more_races: None,
            hispanic_or_latino_ethnicity: None,
            country_of_birth_code: None,
            state_of_birth_abbreviation: None,
            city_of_birth: None,
            public_school_residence_status: None,
        };
        let row = DemographicsCsvRow::from_model(&demo);
        assert_eq!(row.birth_date, "");
        assert_eq!(row.sex, "");
        let back = row.to_model().unwrap();
        assert_eq!(back, demo);
    }

    // -- AcademicSessionCsvRow round trip --

    #[test]
    fn test_academic_session_csv_round_trip() {
        let session = AcademicSession {
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
            children: vec!["gp-001".to_string(), "gp-002".to_string()],
        };
        let row = AcademicSessionCsvRow::from_model(&session);
        let back = row.to_model().unwrap();
        assert_eq!(back, session);
    }

    #[test]
    fn test_academic_session_grading_period() {
        let session = AcademicSession {
            sourced_id: "gp-001".to_string(),
            status: Status::Active,
            date_last_modified: sample_datetime(),
            metadata: None,
            title: "Q1".to_string(),
            start_date: NaiveDate::from_ymd_opt(2025, 8, 15).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2025, 10, 15).unwrap(),
            session_type: SessionType::GradingPeriod,
            parent: Some("term-001".to_string()),
            school_year: "2025".to_string(),
            children: vec![],
        };
        let row = AcademicSessionCsvRow::from_model(&session);
        assert_eq!(row.session_type, "gradingPeriod");
        let back = row.to_model().unwrap();
        assert_eq!(back, session);
    }

    // -- Error cases --

    #[test]
    fn test_invalid_status_returns_error() {
        assert!(csv_to_status("invalid").is_err());
    }

    #[test]
    fn test_invalid_datetime_returns_error() {
        assert!(csv_to_datetime("not-a-date").is_err());
    }

    #[test]
    fn test_invalid_date_returns_error() {
        assert!(csv_to_date("not-a-date").is_err());
    }
}
