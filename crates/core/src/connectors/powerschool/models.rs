use serde::Deserialize;

use crate::models::{
    academic_session::AcademicSession, class::Class, course::Course, demographics::Demographics,
    enrollment::Enrollment, org::Org, user::User,
};

/// Wrapper for the orgs endpoint response.
#[derive(Debug, Deserialize)]
pub struct OrgsResponse {
    #[serde(default)]
    pub orgs: Vec<Org>,
}

/// Wrapper for the academic sessions endpoint response.
#[derive(Debug, Deserialize)]
pub struct AcademicSessionsResponse {
    #[serde(rename = "academicSessions", default)]
    pub academic_sessions: Vec<AcademicSession>,
}

/// Wrapper for the users endpoint response.
#[derive(Debug, Deserialize)]
pub struct UsersResponse {
    #[serde(default)]
    pub users: Vec<User>,
}

/// Wrapper for the courses endpoint response.
#[derive(Debug, Deserialize)]
pub struct CoursesResponse {
    #[serde(default)]
    pub courses: Vec<Course>,
}

/// Wrapper for the classes endpoint response.
#[derive(Debug, Deserialize)]
pub struct ClassesResponse {
    #[serde(default)]
    pub classes: Vec<Class>,
}

/// Wrapper for the enrollments endpoint response.
#[derive(Debug, Deserialize)]
pub struct EnrollmentsResponse {
    #[serde(default)]
    pub enrollments: Vec<Enrollment>,
}

/// Wrapper for the demographics endpoint response.
#[derive(Debug, Deserialize)]
pub struct DemographicsListResponse {
    #[serde(default)]
    pub demographics: Vec<Demographics>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orgs_response_empty() {
        let json = r#"{"orgs":[]}"#;
        let resp: OrgsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.orgs.is_empty());
    }

    #[test]
    fn orgs_response_missing_field_defaults() {
        let json = r#"{}"#;
        let resp: OrgsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.orgs.is_empty());
    }

    #[test]
    fn users_response_empty() {
        let json = r#"{"users":[]}"#;
        let resp: UsersResponse = serde_json::from_str(json).unwrap();
        assert!(resp.users.is_empty());
    }

    #[test]
    fn courses_response_empty() {
        let json = r#"{"courses":[]}"#;
        let resp: CoursesResponse = serde_json::from_str(json).unwrap();
        assert!(resp.courses.is_empty());
    }

    #[test]
    fn classes_response_empty() {
        let json = r#"{"classes":[]}"#;
        let resp: ClassesResponse = serde_json::from_str(json).unwrap();
        assert!(resp.classes.is_empty());
    }

    #[test]
    fn enrollments_response_empty() {
        let json = r#"{"enrollments":[]}"#;
        let resp: EnrollmentsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.enrollments.is_empty());
    }

    #[test]
    fn demographics_response_empty() {
        let json = r#"{"demographics":[]}"#;
        let resp: DemographicsListResponse = serde_json::from_str(json).unwrap();
        assert!(resp.demographics.is_empty());
    }

    #[test]
    fn academic_sessions_response_empty() {
        let json = r#"{"academicSessions":[]}"#;
        let resp: AcademicSessionsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.academic_sessions.is_empty());
    }
}
