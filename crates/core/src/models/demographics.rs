use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use super::common::{Sex, Status};

/// OneRoster Demographics entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Demographics {
    pub sourced_id: String,
    pub status: Status,
    pub date_last_modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_date: Option<NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sex: Option<Sex>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub american_indian_or_alaska_native: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asian: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub black_or_african_american: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_hawaiian_or_other_pacific_islander: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub white: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demographic_race_two_or_more_races: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hispanic_or_latino_ethnicity: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_of_birth_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_of_birth_abbreviation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city_of_birth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_school_residence_status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_demographics() -> Demographics {
        Demographics {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
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
        }
    }

    #[test]
    fn demographics_round_trip() {
        let demo = sample_demographics();
        let json = serde_json::to_string(&demo).unwrap();
        let back: Demographics = serde_json::from_str(&json).unwrap();
        assert_eq!(back, demo);
    }

    #[test]
    fn demographics_camel_case_fields() {
        let demo = sample_demographics();
        let json = serde_json::to_string(&demo).unwrap();
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"dateLastModified\""));
        assert!(json.contains("\"birthDate\""));
        assert!(json.contains("\"americanIndianOrAlaskaNative\""));
        assert!(json.contains("\"blackOrAfricanAmerican\""));
        assert!(json.contains("\"nativeHawaiianOrOtherPacificIslander\""));
        assert!(json.contains("\"demographicRaceTwoOrMoreRaces\""));
        assert!(json.contains("\"hispanicOrLatinoEthnicity\""));
        assert!(json.contains("\"countryOfBirthCode\""));
        assert!(json.contains("\"stateOfBirthAbbreviation\""));
        assert!(json.contains("\"cityOfBirth\""));
    }

    #[test]
    fn demographics_all_optional_omitted() {
        let demo = Demographics {
            sourced_id: "user-002".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
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
        let json = serde_json::to_string(&demo).unwrap();
        // Only required fields should be present
        assert!(json.contains("\"sourcedId\""));
        assert!(json.contains("\"status\""));
        assert!(!json.contains("\"birthDate\""));
        assert!(!json.contains("\"sex\""));
        assert!(!json.contains("\"white\""));
    }
}
