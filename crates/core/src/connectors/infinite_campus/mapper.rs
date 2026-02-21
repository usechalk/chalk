use tracing::warn;

use crate::models::{
    academic_session::AcademicSession, class::Class, common::Status, course::Course,
    demographics::Demographics, enrollment::Enrollment, org::Org, user::User,
};

/// Characters that Infinite Campus may include but are unsupported in downstream systems.
const UNSUPPORTED_CHARS: &[char] = &[
    '`', '\\', ':', '*', '?', '"', '<', '>', '|', '\'', '#', ',', '%', '&',
];

/// Maximum length for org identifier and code fields.
const ORG_FIELD_MAX_LEN: usize = 50;

/// Normalizes data received from the Infinite Campus OneRoster API.
///
/// Beyond standard whitespace trimming, this mapper:
/// - Replaces unsupported characters with underscores
/// - Truncates org identifiers/codes at 50 characters
/// - Logs warnings for records with `tobedeleted` status
pub struct InfiniteCampusMapper;

impl InfiniteCampusMapper {
    /// Replace unsupported characters with underscores and trim whitespace.
    fn sanitize_string(s: &str) -> String {
        let sanitized: String = s
            .chars()
            .map(|c| {
                if UNSUPPORTED_CHARS.contains(&c) {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        sanitized.trim().to_string()
    }

    /// Truncate a string to a maximum byte length, respecting char boundaries.
    fn truncate_to(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            return s.to_string();
        }
        let mut end = max_len;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        s[..end].to_string()
    }

    /// Log a warning if the record has `tobedeleted` status.
    fn warn_if_pending_delete(entity_type: &str, sourced_id: &str, status: &Status) {
        if *status == Status::ToBeDeleted {
            warn!(
                entity_type = entity_type,
                sourced_id = sourced_id,
                "Record has tobedeleted status"
            );
        }
    }

    pub fn normalize_orgs(orgs: Vec<Org>) -> Vec<Org> {
        orgs.into_iter().map(Self::normalize_org).collect()
    }

    fn normalize_org(mut org: Org) -> Org {
        Self::warn_if_pending_delete("org", &org.sourced_id, &org.status);
        org.sourced_id = Self::sanitize_string(&org.sourced_id);
        org.name = Self::sanitize_string(&org.name);
        if let Some(ref mut id) = org.identifier {
            *id = Self::truncate_to(&Self::sanitize_string(id), ORG_FIELD_MAX_LEN);
        }
        if let Some(ref mut parent) = org.parent {
            *parent = Self::sanitize_string(parent);
        }
        org.children = org
            .children
            .into_iter()
            .map(|c| Self::sanitize_string(&c))
            .collect();
        org
    }

    pub fn normalize_academic_sessions(sessions: Vec<AcademicSession>) -> Vec<AcademicSession> {
        sessions
            .into_iter()
            .map(Self::normalize_academic_session)
            .collect()
    }

    fn normalize_academic_session(mut session: AcademicSession) -> AcademicSession {
        Self::warn_if_pending_delete("academic_session", &session.sourced_id, &session.status);
        session.sourced_id = Self::sanitize_string(&session.sourced_id);
        session.title = Self::sanitize_string(&session.title);
        session.school_year = Self::sanitize_string(&session.school_year);
        if let Some(ref mut parent) = session.parent {
            *parent = Self::sanitize_string(parent);
        }
        session.children = session
            .children
            .into_iter()
            .map(|c| Self::sanitize_string(&c))
            .collect();
        session
    }

    pub fn normalize_users(users: Vec<User>) -> Vec<User> {
        users.into_iter().map(Self::normalize_user).collect()
    }

    fn normalize_user(mut user: User) -> User {
        Self::warn_if_pending_delete("user", &user.sourced_id, &user.status);
        user.sourced_id = Self::sanitize_string(&user.sourced_id);
        user.username = Self::sanitize_string(&user.username);
        user.given_name = Self::sanitize_string(&user.given_name);
        user.family_name = Self::sanitize_string(&user.family_name);
        if let Some(ref mut mn) = user.middle_name {
            *mn = Self::sanitize_string(mn);
        }
        if let Some(ref mut email) = user.email {
            *email = Self::sanitize_string(email);
        }
        user.orgs = user
            .orgs
            .into_iter()
            .map(|o| Self::sanitize_string(&o))
            .collect();
        user.agents = user
            .agents
            .into_iter()
            .map(|a| Self::sanitize_string(&a))
            .collect();
        user
    }

    pub fn normalize_courses(courses: Vec<Course>) -> Vec<Course> {
        courses.into_iter().map(Self::normalize_course).collect()
    }

    fn normalize_course(mut course: Course) -> Course {
        Self::warn_if_pending_delete("course", &course.sourced_id, &course.status);
        course.sourced_id = Self::sanitize_string(&course.sourced_id);
        course.title = Self::sanitize_string(&course.title);
        course.org = Self::sanitize_string(&course.org);
        if let Some(ref mut code) = course.course_code {
            *code = Self::sanitize_string(code);
        }
        course
    }

    pub fn normalize_classes(classes: Vec<Class>) -> Vec<Class> {
        classes.into_iter().map(Self::normalize_class).collect()
    }

    fn normalize_class(mut class: Class) -> Class {
        Self::warn_if_pending_delete("class", &class.sourced_id, &class.status);
        class.sourced_id = Self::sanitize_string(&class.sourced_id);
        class.title = Self::sanitize_string(&class.title);
        class.course = Self::sanitize_string(&class.course);
        class.school = Self::sanitize_string(&class.school);
        if let Some(ref mut code) = class.class_code {
            *code = Self::sanitize_string(code);
        }
        class.terms = class
            .terms
            .into_iter()
            .map(|t| Self::sanitize_string(&t))
            .collect();
        class
    }

    pub fn normalize_enrollments(enrollments: Vec<Enrollment>) -> Vec<Enrollment> {
        enrollments
            .into_iter()
            .map(Self::normalize_enrollment)
            .collect()
    }

    fn normalize_enrollment(mut enrollment: Enrollment) -> Enrollment {
        Self::warn_if_pending_delete("enrollment", &enrollment.sourced_id, &enrollment.status);
        enrollment.sourced_id = Self::sanitize_string(&enrollment.sourced_id);
        enrollment.user = Self::sanitize_string(&enrollment.user);
        enrollment.class = Self::sanitize_string(&enrollment.class);
        enrollment.school = Self::sanitize_string(&enrollment.school);
        enrollment
    }

    pub fn normalize_demographics(demographics: Vec<Demographics>) -> Vec<Demographics> {
        demographics
            .into_iter()
            .map(Self::normalize_demographic)
            .collect()
    }

    fn normalize_demographic(mut demo: Demographics) -> Demographics {
        Self::warn_if_pending_delete("demographics", &demo.sourced_id, &demo.status);
        demo.sourced_id = Self::sanitize_string(&demo.sourced_id);
        if let Some(ref mut code) = demo.country_of_birth_code {
            *code = Self::sanitize_string(code);
        }
        if let Some(ref mut state) = demo.state_of_birth_abbreviation {
            *state = Self::sanitize_string(state);
        }
        if let Some(ref mut city) = demo.city_of_birth {
            *city = Self::sanitize_string(city);
        }
        demo
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::common::{
        ClassType, EnrollmentRole, OrgType, RoleType, SessionType, Sex, Status,
    };
    use chrono::{NaiveDate, TimeZone, Utc};

    #[test]
    fn sanitize_replaces_unsupported_chars() {
        assert_eq!(
            InfiniteCampusMapper::sanitize_string("hello`world\\test:foo"),
            "hello_world_test_foo"
        );
        assert_eq!(
            InfiniteCampusMapper::sanitize_string("a*b?c\"d<e>f|g"),
            "a_b_c_d_e_f_g"
        );
        assert_eq!(
            InfiniteCampusMapper::sanitize_string("x'y#z,w%v&u"),
            "x_y_z_w_v_u"
        );
    }

    #[test]
    fn sanitize_trims_whitespace() {
        assert_eq!(InfiniteCampusMapper::sanitize_string("  hello  "), "hello");
        assert_eq!(
            InfiniteCampusMapper::sanitize_string("  test`val  "),
            "test_val"
        );
    }

    #[test]
    fn sanitize_preserves_clean_string() {
        assert_eq!(
            InfiniteCampusMapper::sanitize_string("clean-string_123"),
            "clean-string_123"
        );
    }

    #[test]
    fn truncate_at_50_chars() {
        let long = "a".repeat(60);
        let result = InfiniteCampusMapper::truncate_to(&long, 50);
        assert_eq!(result.len(), 50);

        let short = "abc";
        assert_eq!(InfiniteCampusMapper::truncate_to(short, 50), "abc");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        // Multi-byte character: each is 3 bytes
        let s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u{00e9}"; // 49 ascii + 2-byte e-acute = 51 bytes
        let result = InfiniteCampusMapper::truncate_to(s, 50);
        assert!(result.len() <= 50);
        assert!(result.is_char_boundary(result.len()));
    }

    #[test]
    fn normalize_org_sanitizes_and_truncates() {
        let long_identifier = "a".repeat(60);
        let org = Org {
            sourced_id: "  org`001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "  Test:District  ".to_string(),
            org_type: OrgType::District,
            identifier: Some(long_identifier),
            parent: Some("  parent*001  ".to_string()),
            children: vec!["  child#001  ".to_string()],
        };

        let normalized = InfiniteCampusMapper::normalize_orgs(vec![org]);
        assert_eq!(normalized[0].sourced_id, "org_001");
        assert_eq!(normalized[0].name, "Test_District");
        assert_eq!(
            normalized[0].identifier.as_ref().unwrap().len(),
            ORG_FIELD_MAX_LEN
        );
        assert_eq!(normalized[0].parent.as_deref(), Some("parent_001"));
        assert_eq!(normalized[0].children[0], "child_001");
    }

    #[test]
    fn normalize_user_sanitizes() {
        let user = User {
            sourced_id: "  user`001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "  j:doe  ".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "  John*  ".to_string(),
            family_name: "  Doe  ".to_string(),
            middle_name: Some("  M&  ".to_string()),
            role: RoleType::Student,
            identifier: None,
            email: Some("  jdoe@example.com  ".to_string()),
            sms: None,
            phone: None,
            agents: vec!["  agent#001  ".to_string()],
            orgs: vec!["  org|001  ".to_string()],
            grades: vec!["09".to_string()],
        };

        let normalized = InfiniteCampusMapper::normalize_users(vec![user]);
        assert_eq!(normalized[0].sourced_id, "user_001");
        assert_eq!(normalized[0].username, "j_doe");
        assert_eq!(normalized[0].given_name, "John_");
        assert_eq!(normalized[0].family_name, "Doe");
        assert_eq!(normalized[0].middle_name.as_deref(), Some("M_"));
        assert_eq!(normalized[0].email.as_deref(), Some("jdoe@example.com"));
        assert_eq!(normalized[0].agents[0], "agent_001");
        assert_eq!(normalized[0].orgs[0], "org_001");
    }

    #[test]
    fn normalize_academic_session_sanitizes() {
        let session = AcademicSession {
            sourced_id: "  term`001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "  Fall:2025  ".to_string(),
            start_date: NaiveDate::from_ymd_opt(2025, 8, 15).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2025, 12, 20).unwrap(),
            session_type: SessionType::Term,
            parent: Some("  sy*2025  ".to_string()),
            school_year: "  2025  ".to_string(),
            children: vec![],
        };

        let normalized = InfiniteCampusMapper::normalize_academic_sessions(vec![session]);
        assert_eq!(normalized[0].sourced_id, "term_001");
        assert_eq!(normalized[0].title, "Fall_2025");
        assert_eq!(normalized[0].school_year, "2025");
        assert_eq!(normalized[0].parent.as_deref(), Some("sy_2025"));
    }

    #[test]
    fn normalize_course_sanitizes() {
        let course = Course {
            sourced_id: "  course`001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "  Algebra:I  ".to_string(),
            school_year: Some("2025".to_string()),
            course_code: Some("  ALG*1  ".to_string()),
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            org: "  org|001  ".to_string(),
        };

        let normalized = InfiniteCampusMapper::normalize_courses(vec![course]);
        assert_eq!(normalized[0].sourced_id, "course_001");
        assert_eq!(normalized[0].title, "Algebra_I");
        assert_eq!(normalized[0].course_code.as_deref(), Some("ALG_1"));
        assert_eq!(normalized[0].org, "org_001");
    }

    #[test]
    fn normalize_class_sanitizes() {
        let class = Class {
            sourced_id: "  class`001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "  Algebra:I - P1  ".to_string(),
            class_code: Some("  ALG*1-P1  ".to_string()),
            class_type: ClassType::Scheduled,
            location: None,
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            course: "  course#001  ".to_string(),
            school: "  org|002  ".to_string(),
            terms: vec!["  term%001  ".to_string()],
            periods: vec!["1".to_string()],
        };

        let normalized = InfiniteCampusMapper::normalize_classes(vec![class]);
        assert_eq!(normalized[0].sourced_id, "class_001");
        assert_eq!(normalized[0].title, "Algebra_I - P1");
        assert_eq!(normalized[0].class_code.as_deref(), Some("ALG_1-P1"));
        assert_eq!(normalized[0].course, "course_001");
        assert_eq!(normalized[0].school, "org_002");
        assert_eq!(normalized[0].terms[0], "term_001");
    }

    #[test]
    fn normalize_enrollment_sanitizes() {
        let enrollment = Enrollment {
            sourced_id: "  enr`001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "  user*001  ".to_string(),
            class: "  class#001  ".to_string(),
            school: "  org|002  ".to_string(),
            role: EnrollmentRole::Student,
            primary: Some(true),
            begin_date: None,
            end_date: None,
        };

        let normalized = InfiniteCampusMapper::normalize_enrollments(vec![enrollment]);
        assert_eq!(normalized[0].sourced_id, "enr_001");
        assert_eq!(normalized[0].user, "user_001");
        assert_eq!(normalized[0].class, "class_001");
        assert_eq!(normalized[0].school, "org_002");
    }

    #[test]
    fn normalize_demographics_sanitizes() {
        let demo = Demographics {
            sourced_id: "  user`001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            birth_date: Some(NaiveDate::from_ymd_opt(2009, 3, 15).unwrap()),
            sex: Some(Sex::Male),
            american_indian_or_alaska_native: None,
            asian: None,
            black_or_african_american: None,
            native_hawaiian_or_other_pacific_islander: None,
            white: None,
            demographic_race_two_or_more_races: None,
            hispanic_or_latino_ethnicity: None,
            country_of_birth_code: Some("  US  ".to_string()),
            state_of_birth_abbreviation: Some("  IL  ".to_string()),
            city_of_birth: Some("  Spring:field  ".to_string()),
            public_school_residence_status: None,
        };

        let normalized = InfiniteCampusMapper::normalize_demographics(vec![demo]);
        assert_eq!(normalized[0].sourced_id, "user_001");
        assert_eq!(normalized[0].country_of_birth_code.as_deref(), Some("US"));
        assert_eq!(
            normalized[0].state_of_birth_abbreviation.as_deref(),
            Some("IL")
        );
        assert_eq!(normalized[0].city_of_birth.as_deref(), Some("Spring_field"));
    }

    #[test]
    fn normalize_preserves_clean_data() {
        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Clean District".to_string(),
            org_type: OrgType::District,
            identifier: Some("ID001".to_string()),
            parent: None,
            children: vec![],
        };

        let normalized = InfiniteCampusMapper::normalize_orgs(vec![org.clone()]);
        assert_eq!(normalized[0].sourced_id, org.sourced_id);
        assert_eq!(normalized[0].name, org.name);
        assert_eq!(normalized[0].identifier, org.identifier);
    }

    #[test]
    fn normalize_empty_vecs() {
        assert!(InfiniteCampusMapper::normalize_orgs(vec![]).is_empty());
        assert!(InfiniteCampusMapper::normalize_users(vec![]).is_empty());
        assert!(InfiniteCampusMapper::normalize_academic_sessions(vec![]).is_empty());
        assert!(InfiniteCampusMapper::normalize_courses(vec![]).is_empty());
        assert!(InfiniteCampusMapper::normalize_classes(vec![]).is_empty());
        assert!(InfiniteCampusMapper::normalize_enrollments(vec![]).is_empty());
        assert!(InfiniteCampusMapper::normalize_demographics(vec![]).is_empty());
    }

    #[test]
    fn tobedeleted_records_are_kept() {
        let org = Org {
            sourced_id: "org-deleted".to_string(),
            status: Status::ToBeDeleted,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Deleted Org".to_string(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        };

        let normalized = InfiniteCampusMapper::normalize_orgs(vec![org]);
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].status, Status::ToBeDeleted);
        assert_eq!(normalized[0].sourced_id, "org-deleted");
    }
}
