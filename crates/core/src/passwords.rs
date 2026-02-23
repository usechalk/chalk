//! Default password generation from user/demographics data using configurable patterns.

use crate::error::{ChalkError, Result};
use crate::models::common::RoleType;
use crate::models::demographics::Demographics;
use crate::models::user::User;

/// Generates passwords from a pattern string by resolving placeholders
/// against User and Demographics data.
pub struct PasswordGenerator<'a> {
    pattern: &'a str,
    roles: &'a [String],
}

impl<'a> PasswordGenerator<'a> {
    /// Create a new generator with the given pattern and allowed roles.
    pub fn new(pattern: &'a str, roles: &'a [String]) -> Self {
        Self { pattern, roles }
    }

    /// Check whether a user's role matches the configured roles.
    pub fn matches_role(&self, user: &User) -> bool {
        if self.roles.is_empty() {
            return false;
        }
        let role_str = role_to_string(&user.role);
        self.roles.iter().any(|r| r.eq_ignore_ascii_case(&role_str))
    }

    /// Generate a password for a user by resolving all placeholders in the pattern.
    ///
    /// Returns `Err` if a placeholder references data that is not available
    /// (e.g., `{birthYear}` when no demographics are provided).
    pub fn generate_for_user(
        &self,
        user: &User,
        demographics: Option<&Demographics>,
    ) -> Result<String> {
        let mut result = self.pattern.to_string();
        let mut pos = 0;

        while let Some(start) = result[pos..].find('{') {
            let start = pos + start;
            let end = result[start..]
                .find('}')
                .map(|i| start + i)
                .ok_or_else(|| {
                    ChalkError::Config(format!(
                        "unclosed placeholder in password pattern: {}",
                        self.pattern
                    ))
                })?;

            let placeholder = &result[start + 1..end];
            let value = resolve_placeholder(placeholder, user, demographics)?;

            result.replace_range(start..=end, &value);
            pos = start + value.len();
        }

        if result.is_empty() {
            return Err(ChalkError::Config(
                "password pattern resolved to empty string".into(),
            ));
        }

        Ok(result)
    }
}

fn resolve_placeholder(
    placeholder: &str,
    user: &User,
    demographics: Option<&Demographics>,
) -> Result<String> {
    match placeholder {
        "firstName" => Ok(user.given_name.clone()),
        "lastName" => Ok(user.family_name.clone()),
        "username" => Ok(user.username.clone()),
        "identifier" => user
            .identifier
            .clone()
            .ok_or_else(|| missing_field_error("identifier", &user.sourced_id)),
        "email" => user
            .email
            .clone()
            .ok_or_else(|| missing_field_error("email", &user.sourced_id)),
        "sourcedId" => Ok(user.sourced_id.clone()),
        "birthYear" => {
            let demo = demographics
                .ok_or_else(|| missing_field_error("demographics (birthYear)", &user.sourced_id))?;
            let date = demo
                .birth_date
                .ok_or_else(|| missing_field_error("birth_date", &user.sourced_id))?;
            Ok(date.format("%Y").to_string())
        }
        "birthDate" => {
            let demo = demographics
                .ok_or_else(|| missing_field_error("demographics (birthDate)", &user.sourced_id))?;
            let date = demo
                .birth_date
                .ok_or_else(|| missing_field_error("birth_date", &user.sourced_id))?;
            Ok(date.format("%m%d").to_string())
        }
        "grade" => user
            .grades
            .first()
            .cloned()
            .ok_or_else(|| missing_field_error("grade", &user.sourced_id)),
        _ => Err(ChalkError::Config(format!(
            "unknown password placeholder: {{{placeholder}}}"
        ))),
    }
}

fn missing_field_error(field: &str, user_id: &str) -> ChalkError {
    ChalkError::Config(format!(
        "password pattern requires {field} but it is missing for user {user_id}"
    ))
}

fn role_to_string(role: &RoleType) -> String {
    match role {
        RoleType::Administrator => "administrator".to_string(),
        RoleType::Aide => "aide".to_string(),
        RoleType::Guardian => "guardian".to_string(),
        RoleType::Parent => "parent".to_string(),
        RoleType::Proctor => "proctor".to_string(),
        RoleType::Student => "student".to_string(),
        RoleType::Teacher => "teacher".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::common::Status;
    use chrono::{NaiveDate, TimeZone, Utc};

    fn sample_user() -> User {
        User {
            sourced_id: "user-002".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "asmith".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Alice".to_string(),
            family_name: "Smith".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: Some("S001".to_string()),
            email: Some("asmith@springfield.edu".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec!["09".to_string()],
        }
    }

    fn sample_demographics() -> Demographics {
        Demographics {
            sourced_id: "user-002".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            birth_date: Some(NaiveDate::from_ymd_opt(2009, 3, 15).unwrap()),
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
        }
    }

    #[test]
    fn generate_last_name_birth_year() {
        let roles: Vec<String> = vec!["student".into()];
        let gen = PasswordGenerator::new("{lastName}{birthYear}", &roles);
        let user = sample_user();
        let demo = sample_demographics();
        let password = gen.generate_for_user(&user, Some(&demo)).unwrap();
        assert_eq!(password, "Smith2009");
    }

    #[test]
    fn generate_first_name_dot_identifier() {
        let roles: Vec<String> = vec!["student".into()];
        let gen = PasswordGenerator::new("{firstName}.{identifier}", &roles);
        let user = sample_user();
        let password = gen.generate_for_user(&user, None).unwrap();
        assert_eq!(password, "Alice.S001");
    }

    #[test]
    fn generate_username_birth_date() {
        let roles: Vec<String> = vec!["student".into()];
        let gen = PasswordGenerator::new("{username}{birthDate}", &roles);
        let user = sample_user();
        let demo = sample_demographics();
        let password = gen.generate_for_user(&user, Some(&demo)).unwrap();
        assert_eq!(password, "asmith0315");
    }

    #[test]
    fn generate_sourced_id_only() {
        let gen = PasswordGenerator::new("{sourcedId}", &[]);
        let user = sample_user();
        let password = gen.generate_for_user(&user, None).unwrap();
        assert_eq!(password, "user-002");
    }

    #[test]
    fn generate_email_only() {
        let gen = PasswordGenerator::new("{email}", &[]);
        let user = sample_user();
        let password = gen.generate_for_user(&user, None).unwrap();
        assert_eq!(password, "asmith@springfield.edu");
    }

    #[test]
    fn generate_grade_placeholder() {
        let gen = PasswordGenerator::new("{lastName}{grade}", &[]);
        let user = sample_user();
        let password = gen.generate_for_user(&user, None).unwrap();
        assert_eq!(password, "Smith09");
    }

    #[test]
    fn generate_plain_text_prefix() {
        let gen = PasswordGenerator::new("chalk-{username}-{birthYear}", &[]);
        let user = sample_user();
        let demo = sample_demographics();
        let password = gen.generate_for_user(&user, Some(&demo)).unwrap();
        assert_eq!(password, "chalk-asmith-2009");
    }

    #[test]
    fn error_on_missing_demographics() {
        let gen = PasswordGenerator::new("{lastName}{birthYear}", &[]);
        let user = sample_user();
        let err = gen.generate_for_user(&user, None).unwrap_err();
        assert!(err.to_string().contains("birthYear"));
    }

    #[test]
    fn error_on_missing_birth_date() {
        let gen = PasswordGenerator::new("{birthYear}", &[]);
        let user = sample_user();
        let mut demo = sample_demographics();
        demo.birth_date = None;
        let err = gen.generate_for_user(&user, Some(&demo)).unwrap_err();
        assert!(err.to_string().contains("birth_date"));
    }

    #[test]
    fn error_on_missing_identifier() {
        let gen = PasswordGenerator::new("{identifier}", &[]);
        let mut user = sample_user();
        user.identifier = None;
        let err = gen.generate_for_user(&user, None).unwrap_err();
        assert!(err.to_string().contains("identifier"));
    }

    #[test]
    fn error_on_missing_email() {
        let gen = PasswordGenerator::new("{email}", &[]);
        let mut user = sample_user();
        user.email = None;
        let err = gen.generate_for_user(&user, None).unwrap_err();
        assert!(err.to_string().contains("email"));
    }

    #[test]
    fn error_on_missing_grade() {
        let gen = PasswordGenerator::new("{grade}", &[]);
        let mut user = sample_user();
        user.grades.clear();
        let err = gen.generate_for_user(&user, None).unwrap_err();
        assert!(err.to_string().contains("grade"));
    }

    #[test]
    fn error_on_unknown_placeholder() {
        let gen = PasswordGenerator::new("{unknown}", &[]);
        let user = sample_user();
        let err = gen.generate_for_user(&user, None).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn error_on_unclosed_placeholder() {
        let gen = PasswordGenerator::new("{lastName", &[]);
        let user = sample_user();
        let err = gen.generate_for_user(&user, None).unwrap_err();
        assert!(err.to_string().contains("unclosed"));
    }

    #[test]
    fn matches_role_student() {
        let roles: Vec<String> = vec!["student".into(), "teacher".into()];
        let gen = PasswordGenerator::new("{lastName}", &roles);
        let user = sample_user();
        assert!(gen.matches_role(&user));
    }

    #[test]
    fn matches_role_case_insensitive() {
        let roles: Vec<String> = vec!["Student".into()];
        let gen = PasswordGenerator::new("{lastName}", &roles);
        let user = sample_user();
        assert!(gen.matches_role(&user));
    }

    #[test]
    fn does_not_match_unmatched_role() {
        let roles: Vec<String> = vec!["teacher".into()];
        let gen = PasswordGenerator::new("{lastName}", &roles);
        let user = sample_user();
        assert!(!gen.matches_role(&user));
    }

    #[test]
    fn does_not_match_empty_roles() {
        let gen = PasswordGenerator::new("{lastName}", &[]);
        let user = sample_user();
        assert!(!gen.matches_role(&user));
    }

    #[test]
    fn matches_teacher_role() {
        let roles: Vec<String> = vec!["teacher".into()];
        let gen = PasswordGenerator::new("{lastName}", &roles);
        let mut user = sample_user();
        user.role = RoleType::Teacher;
        assert!(gen.matches_role(&user));
    }

    #[test]
    fn matches_administrator_role() {
        let roles: Vec<String> = vec!["administrator".into()];
        let gen = PasswordGenerator::new("{lastName}", &roles);
        let mut user = sample_user();
        user.role = RoleType::Administrator;
        assert!(gen.matches_role(&user));
    }

    #[test]
    fn generate_no_placeholders() {
        let gen = PasswordGenerator::new("static-password", &[]);
        let user = sample_user();
        let password = gen.generate_for_user(&user, None).unwrap();
        assert_eq!(password, "static-password");
    }

    #[test]
    fn generate_multiple_same_placeholder() {
        let gen = PasswordGenerator::new("{firstName}{firstName}", &[]);
        let user = sample_user();
        let password = gen.generate_for_user(&user, None).unwrap();
        assert_eq!(password, "AliceAlice");
    }

    #[test]
    fn birth_date_zero_padded() {
        let gen = PasswordGenerator::new("{birthDate}", &[]);
        let user = sample_user();
        let mut demo = sample_demographics();
        demo.birth_date = Some(NaiveDate::from_ymd_opt(2010, 1, 5).unwrap());
        let password = gen.generate_for_user(&user, Some(&demo)).unwrap();
        assert_eq!(password, "0105");
    }
}
