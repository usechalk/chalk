use crate::models::{
    academic_session::AcademicSession, class::Class, course::Course, demographics::Demographics,
    enrollment::Enrollment, org::Org, user::User,
};

/// Normalizes data received from the PowerSchool OneRoster API.
///
/// Since PowerSchool returns data in OneRoster format, the mapper mainly
/// handles trimming whitespace on sourced_ids and ensuring consistency.
pub struct PowerSchoolMapper;

impl PowerSchoolMapper {
    /// Normalize a list of orgs from the API.
    pub fn normalize_orgs(orgs: Vec<Org>) -> Vec<Org> {
        orgs.into_iter().map(Self::normalize_org).collect()
    }

    /// Normalize a single org.
    fn normalize_org(mut org: Org) -> Org {
        org.sourced_id = org.sourced_id.trim().to_string();
        org.name = org.name.trim().to_string();
        if let Some(ref mut parent) = org.parent {
            *parent = parent.trim().to_string();
        }
        org.children = org
            .children
            .into_iter()
            .map(|c| c.trim().to_string())
            .collect();
        org
    }

    /// Normalize a list of academic sessions from the API.
    pub fn normalize_academic_sessions(sessions: Vec<AcademicSession>) -> Vec<AcademicSession> {
        sessions
            .into_iter()
            .map(Self::normalize_academic_session)
            .collect()
    }

    /// Normalize a single academic session.
    fn normalize_academic_session(mut session: AcademicSession) -> AcademicSession {
        session.sourced_id = session.sourced_id.trim().to_string();
        session.title = session.title.trim().to_string();
        session.school_year = session.school_year.trim().to_string();
        if let Some(ref mut parent) = session.parent {
            *parent = parent.trim().to_string();
        }
        session.children = session
            .children
            .into_iter()
            .map(|c| c.trim().to_string())
            .collect();
        session
    }

    /// Normalize a list of users from the API.
    pub fn normalize_users(users: Vec<User>) -> Vec<User> {
        users.into_iter().map(Self::normalize_user).collect()
    }

    /// Normalize a single user.
    fn normalize_user(mut user: User) -> User {
        user.sourced_id = user.sourced_id.trim().to_string();
        user.username = user.username.trim().to_string();
        user.given_name = user.given_name.trim().to_string();
        user.family_name = user.family_name.trim().to_string();
        if let Some(ref mut mn) = user.middle_name {
            *mn = mn.trim().to_string();
        }
        if let Some(ref mut email) = user.email {
            *email = email.trim().to_string();
        }
        user.orgs = user
            .orgs
            .into_iter()
            .map(|o| o.trim().to_string())
            .collect();
        user.agents = user
            .agents
            .into_iter()
            .map(|a| a.trim().to_string())
            .collect();
        user
    }

    /// Normalize a list of courses from the API.
    pub fn normalize_courses(courses: Vec<Course>) -> Vec<Course> {
        courses.into_iter().map(Self::normalize_course).collect()
    }

    /// Normalize a single course.
    fn normalize_course(mut course: Course) -> Course {
        course.sourced_id = course.sourced_id.trim().to_string();
        course.title = course.title.trim().to_string();
        course.org = course.org.trim().to_string();
        if let Some(ref mut code) = course.course_code {
            *code = code.trim().to_string();
        }
        course
    }

    /// Normalize a list of classes from the API.
    pub fn normalize_classes(classes: Vec<Class>) -> Vec<Class> {
        classes.into_iter().map(Self::normalize_class).collect()
    }

    /// Normalize a single class.
    fn normalize_class(mut class: Class) -> Class {
        class.sourced_id = class.sourced_id.trim().to_string();
        class.title = class.title.trim().to_string();
        class.course = class.course.trim().to_string();
        class.school = class.school.trim().to_string();
        if let Some(ref mut code) = class.class_code {
            *code = code.trim().to_string();
        }
        class.terms = class
            .terms
            .into_iter()
            .map(|t| t.trim().to_string())
            .collect();
        class
    }

    /// Normalize a list of enrollments from the API.
    pub fn normalize_enrollments(enrollments: Vec<Enrollment>) -> Vec<Enrollment> {
        enrollments
            .into_iter()
            .map(Self::normalize_enrollment)
            .collect()
    }

    /// Normalize a single enrollment.
    fn normalize_enrollment(mut enrollment: Enrollment) -> Enrollment {
        enrollment.sourced_id = enrollment.sourced_id.trim().to_string();
        enrollment.user = enrollment.user.trim().to_string();
        enrollment.class = enrollment.class.trim().to_string();
        enrollment.school = enrollment.school.trim().to_string();
        enrollment
    }

    /// Normalize a list of demographics from the API.
    pub fn normalize_demographics(demographics: Vec<Demographics>) -> Vec<Demographics> {
        demographics
            .into_iter()
            .map(Self::normalize_demographic)
            .collect()
    }

    /// Normalize a single demographics record.
    fn normalize_demographic(mut demo: Demographics) -> Demographics {
        demo.sourced_id = demo.sourced_id.trim().to_string();
        if let Some(ref mut code) = demo.country_of_birth_code {
            *code = code.trim().to_string();
        }
        if let Some(ref mut state) = demo.state_of_birth_abbreviation {
            *state = state.trim().to_string();
        }
        if let Some(ref mut city) = demo.city_of_birth {
            *city = city.trim().to_string();
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
    fn normalize_org_trims_whitespace() {
        let org = Org {
            sourced_id: "  org-001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "  Test District  ".to_string(),
            org_type: OrgType::District,
            identifier: None,
            parent: Some("  parent-001  ".to_string()),
            children: vec!["  child-001  ".to_string()],
        };

        let normalized = PowerSchoolMapper::normalize_orgs(vec![org]);
        assert_eq!(normalized[0].sourced_id, "org-001");
        assert_eq!(normalized[0].name, "Test District");
        assert_eq!(normalized[0].parent.as_deref(), Some("parent-001"));
        assert_eq!(normalized[0].children[0], "child-001");
    }

    #[test]
    fn normalize_user_trims_whitespace() {
        let user = User {
            sourced_id: "  user-001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "  jdoe  ".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "  John  ".to_string(),
            family_name: "  Doe  ".to_string(),
            middle_name: Some("  M  ".to_string()),
            role: RoleType::Student,
            identifier: None,
            email: Some("  jdoe@example.com  ".to_string()),
            sms: None,
            phone: None,
            agents: vec!["  agent-001  ".to_string()],
            orgs: vec!["  org-001  ".to_string()],
            grades: vec!["09".to_string()],
        };

        let normalized = PowerSchoolMapper::normalize_users(vec![user]);
        assert_eq!(normalized[0].sourced_id, "user-001");
        assert_eq!(normalized[0].username, "jdoe");
        assert_eq!(normalized[0].given_name, "John");
        assert_eq!(normalized[0].family_name, "Doe");
        assert_eq!(normalized[0].middle_name.as_deref(), Some("M"));
        assert_eq!(normalized[0].email.as_deref(), Some("jdoe@example.com"));
        assert_eq!(normalized[0].agents[0], "agent-001");
        assert_eq!(normalized[0].orgs[0], "org-001");
    }

    #[test]
    fn normalize_academic_session_trims_whitespace() {
        let session = AcademicSession {
            sourced_id: "  term-001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "  Fall 2025  ".to_string(),
            start_date: NaiveDate::from_ymd_opt(2025, 8, 15).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2025, 12, 20).unwrap(),
            session_type: SessionType::Term,
            parent: Some("  sy-2025  ".to_string()),
            school_year: "  2025  ".to_string(),
            children: vec![],
        };

        let normalized = PowerSchoolMapper::normalize_academic_sessions(vec![session]);
        assert_eq!(normalized[0].sourced_id, "term-001");
        assert_eq!(normalized[0].title, "Fall 2025");
        assert_eq!(normalized[0].school_year, "2025");
        assert_eq!(normalized[0].parent.as_deref(), Some("sy-2025"));
    }

    #[test]
    fn normalize_course_trims_whitespace() {
        let course = Course {
            sourced_id: "  course-001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "  Algebra I  ".to_string(),
            school_year: Some("2025".to_string()),
            course_code: Some("  ALG1  ".to_string()),
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            org: "  org-001  ".to_string(),
        };

        let normalized = PowerSchoolMapper::normalize_courses(vec![course]);
        assert_eq!(normalized[0].sourced_id, "course-001");
        assert_eq!(normalized[0].title, "Algebra I");
        assert_eq!(normalized[0].course_code.as_deref(), Some("ALG1"));
        assert_eq!(normalized[0].org, "org-001");
    }

    #[test]
    fn normalize_class_trims_whitespace() {
        let class = Class {
            sourced_id: "  class-001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "  Algebra I - P1  ".to_string(),
            class_code: Some("  ALG1-P1  ".to_string()),
            class_type: ClassType::Scheduled,
            location: None,
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            course: "  course-001  ".to_string(),
            school: "  org-002  ".to_string(),
            terms: vec!["  term-001  ".to_string()],
            periods: vec!["1".to_string()],
        };

        let normalized = PowerSchoolMapper::normalize_classes(vec![class]);
        assert_eq!(normalized[0].sourced_id, "class-001");
        assert_eq!(normalized[0].title, "Algebra I - P1");
        assert_eq!(normalized[0].class_code.as_deref(), Some("ALG1-P1"));
        assert_eq!(normalized[0].course, "course-001");
        assert_eq!(normalized[0].school, "org-002");
        assert_eq!(normalized[0].terms[0], "term-001");
    }

    #[test]
    fn normalize_enrollment_trims_whitespace() {
        let enrollment = Enrollment {
            sourced_id: "  enr-001  ".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "  user-001  ".to_string(),
            class: "  class-001  ".to_string(),
            school: "  org-002  ".to_string(),
            role: EnrollmentRole::Student,
            primary: Some(true),
            begin_date: None,
            end_date: None,
        };

        let normalized = PowerSchoolMapper::normalize_enrollments(vec![enrollment]);
        assert_eq!(normalized[0].sourced_id, "enr-001");
        assert_eq!(normalized[0].user, "user-001");
        assert_eq!(normalized[0].class, "class-001");
        assert_eq!(normalized[0].school, "org-002");
    }

    #[test]
    fn normalize_demographics_trims_whitespace() {
        let demo = Demographics {
            sourced_id: "  user-001  ".to_string(),
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
            city_of_birth: Some("  Springfield  ".to_string()),
            public_school_residence_status: None,
        };

        let normalized = PowerSchoolMapper::normalize_demographics(vec![demo]);
        assert_eq!(normalized[0].sourced_id, "user-001");
        assert_eq!(normalized[0].country_of_birth_code.as_deref(), Some("US"));
        assert_eq!(
            normalized[0].state_of_birth_abbreviation.as_deref(),
            Some("IL")
        );
        assert_eq!(normalized[0].city_of_birth.as_deref(), Some("Springfield"));
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

        let normalized = PowerSchoolMapper::normalize_orgs(vec![org.clone()]);
        assert_eq!(normalized[0].sourced_id, org.sourced_id);
        assert_eq!(normalized[0].name, org.name);
    }

    #[test]
    fn normalize_empty_vecs() {
        assert!(PowerSchoolMapper::normalize_orgs(vec![]).is_empty());
        assert!(PowerSchoolMapper::normalize_users(vec![]).is_empty());
        assert!(PowerSchoolMapper::normalize_academic_sessions(vec![]).is_empty());
        assert!(PowerSchoolMapper::normalize_courses(vec![]).is_empty());
        assert!(PowerSchoolMapper::normalize_classes(vec![]).is_empty());
        assert!(PowerSchoolMapper::normalize_enrollments(vec![]).is_empty());
        assert!(PowerSchoolMapper::normalize_demographics(vec![]).is_empty());
    }
}
