use tracing::{error, info};

use crate::connectors::SisConnector;
use crate::db::repository::ChalkRepository;
use crate::error::Result;
use crate::models::sync::{SyncRun, SyncStatus};

/// Engine that orchestrates a full data sync from an SIS connector into the database.
pub struct SyncEngine<R: ChalkRepository> {
    repo: R,
}

impl<R: ChalkRepository> SyncEngine<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    /// Run a full sync: fetch data from the connector and persist it in dependency order.
    pub async fn run(&self, connector: &dyn SisConnector) -> Result<SyncRun> {
        let provider = connector.provider_name().to_string();
        info!(provider = %provider, "Starting sync run");

        let sync_run = self.repo.create_sync_run(&provider).await?;
        let sync_id = sync_run.id;

        match self.execute_sync(connector, sync_id).await {
            Ok(sync_run) => Ok(sync_run),
            Err(e) => {
                error!(sync_id, error = %e, "Sync run failed");
                let _ = self
                    .repo
                    .update_sync_status(sync_id, SyncStatus::Failed, Some(&e.to_string()))
                    .await;
                // Return the failed sync run
                let failed_run = self.repo.get_sync_run(sync_id).await?;
                Ok(failed_run.unwrap_or(sync_run))
            }
        }
    }

    async fn execute_sync(&self, connector: &dyn SisConnector, sync_id: i64) -> Result<SyncRun> {
        let payload = connector.full_sync().await?;

        // Persist in dependency order:
        // 1. Orgs (no dependencies)
        info!(count = payload.orgs.len(), "Persisting orgs");
        for org in &payload.orgs {
            self.repo.upsert_org(org).await?;
        }

        // 2. Academic sessions (no dependencies)
        info!(
            count = payload.academic_sessions.len(),
            "Persisting academic sessions"
        );
        for session in &payload.academic_sessions {
            self.repo.upsert_academic_session(session).await?;
        }

        // 3. Users (depend on orgs)
        info!(count = payload.users.len(), "Persisting users");
        for user in &payload.users {
            self.repo.upsert_user(user).await?;
        }

        // 4. Courses (depend on orgs)
        info!(count = payload.courses.len(), "Persisting courses");
        for course in &payload.courses {
            self.repo.upsert_course(course).await?;
        }

        // 5. Classes (depend on courses, orgs, academic_sessions)
        info!(count = payload.classes.len(), "Persisting classes");
        for class in &payload.classes {
            self.repo.upsert_class(class).await?;
        }

        // 6. Enrollments (depend on users, classes, orgs)
        info!(count = payload.enrollments.len(), "Persisting enrollments");
        for enrollment in &payload.enrollments {
            self.repo.upsert_enrollment(enrollment).await?;
        }

        // 7. Demographics (depend on users)
        info!(
            count = payload.demographics.len(),
            "Persisting demographics"
        );
        for demo in &payload.demographics {
            self.repo.upsert_demographics(demo).await?;
        }

        // Update counts
        self.repo
            .update_sync_counts(
                sync_id,
                payload.users.len() as i64,
                payload.orgs.len() as i64,
                payload.courses.len() as i64,
                payload.classes.len() as i64,
                payload.enrollments.len() as i64,
            )
            .await?;

        // Mark completed
        self.repo
            .update_sync_status(sync_id, SyncStatus::Completed, None)
            .await?;

        let final_run = self.repo.get_sync_run(sync_id).await?;
        Ok(final_run.expect("Sync run should exist after completion"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::SyncPayload;
    use crate::db::repository::{
        AcademicSessionRepository, ClassRepository, CourseRepository, DemographicsRepository,
        EnrollmentRepository, OrgRepository, SyncRepository, UserRepository,
    };
    use crate::db::sqlite::SqliteRepository;
    use crate::db::DatabasePool;
    use crate::error::ChalkError;
    use crate::models::{
        academic_session::AcademicSession,
        class::Class,
        common::{ClassType, EnrollmentRole, OrgType, RoleType, SessionType, Sex, Status},
        course::Course,
        demographics::Demographics,
        enrollment::Enrollment,
        org::Org,
        user::User,
    };
    use async_trait::async_trait;
    use chrono::{NaiveDate, TimeZone, Utc};

    struct MockConnector {
        payload: SyncPayload,
        should_fail: bool,
    }

    #[async_trait]
    impl SisConnector for MockConnector {
        async fn full_sync(&self) -> Result<SyncPayload> {
            if self.should_fail {
                return Err(ChalkError::Sync("Mock connector failure".to_string()));
            }

            // Clone the payload data
            Ok(SyncPayload {
                orgs: self.payload.orgs.clone(),
                academic_sessions: self.payload.academic_sessions.clone(),
                users: self.payload.users.clone(),
                courses: self.payload.courses.clone(),
                classes: self.payload.classes.clone(),
                enrollments: self.payload.enrollments.clone(),
                demographics: self.payload.demographics.clone(),
            })
        }

        async fn test_connection(&self) -> Result<()> {
            if self.should_fail {
                return Err(ChalkError::Sync("Connection test failed".to_string()));
            }
            Ok(())
        }

        fn provider_name(&self) -> &str {
            "mock_sis"
        }
    }

    async fn setup_repo() -> SqliteRepository {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        match pool {
            DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        }
    }

    fn sample_org() -> Org {
        Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Springfield District".to_string(),
            org_type: OrgType::District,
            identifier: Some("SSD001".to_string()),
            parent: None,
            children: vec![],
        }
    }

    fn sample_school() -> Org {
        Org {
            sourced_id: "org-002".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Springfield High".to_string(),
            org_type: OrgType::School,
            identifier: None,
            parent: Some("org-001".to_string()),
            children: vec![],
        }
    }

    fn sample_academic_session() -> AcademicSession {
        AcademicSession {
            sourced_id: "term-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Fall 2025".to_string(),
            start_date: NaiveDate::from_ymd_opt(2025, 8, 15).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2025, 12, 20).unwrap(),
            session_type: SessionType::Term,
            parent: None,
            school_year: "2025".to_string(),
            children: vec![],
        }
    }

    fn sample_user() -> User {
        User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec!["09".to_string()],
        }
    }

    fn sample_course() -> Course {
        Course {
            sourced_id: "course-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Algebra I".to_string(),
            school_year: Some("2025".to_string()),
            course_code: Some("ALG1".to_string()),
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            org: "org-001".to_string(),
        }
    }

    fn sample_class() -> Class {
        Class {
            sourced_id: "class-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            title: "Algebra I - P1".to_string(),
            class_code: Some("ALG1-P1".to_string()),
            class_type: ClassType::Scheduled,
            location: Some("Room 101".to_string()),
            grades: vec!["09".to_string()],
            subjects: vec!["Mathematics".to_string()],
            course: "course-001".to_string(),
            school: "org-002".to_string(),
            terms: vec!["term-001".to_string()],
            periods: vec!["1".to_string()],
        }
    }

    fn sample_enrollment() -> Enrollment {
        Enrollment {
            sourced_id: "enr-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            user: "user-001".to_string(),
            class: "class-001".to_string(),
            school: "org-002".to_string(),
            role: EnrollmentRole::Student,
            primary: None,
            begin_date: Some(NaiveDate::from_ymd_opt(2025, 8, 15).unwrap()),
            end_date: Some(NaiveDate::from_ymd_opt(2026, 6, 1).unwrap()),
        }
    }

    fn sample_demographics() -> Demographics {
        Demographics {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            birth_date: Some(NaiveDate::from_ymd_opt(2009, 3, 15).unwrap()),
            sex: Some(Sex::Male),
            american_indian_or_alaska_native: None,
            asian: None,
            black_or_african_american: None,
            native_hawaiian_or_other_pacific_islander: None,
            white: Some(true),
            demographic_race_two_or_more_races: None,
            hispanic_or_latino_ethnicity: None,
            country_of_birth_code: Some("US".to_string()),
            state_of_birth_abbreviation: Some("IL".to_string()),
            city_of_birth: Some("Springfield".to_string()),
            public_school_residence_status: None,
        }
    }

    fn full_payload() -> SyncPayload {
        SyncPayload {
            orgs: vec![sample_org(), sample_school()],
            academic_sessions: vec![sample_academic_session()],
            users: vec![sample_user()],
            courses: vec![sample_course()],
            classes: vec![sample_class()],
            enrollments: vec![sample_enrollment()],
            demographics: vec![sample_demographics()],
        }
    }

    #[tokio::test]
    async fn sync_engine_full_sync_persists_all_entities() {
        let repo = setup_repo().await;
        let engine = SyncEngine::new(repo);

        let connector = MockConnector {
            payload: full_payload(),
            should_fail: false,
        };

        let sync_run = engine.run(&connector).await.unwrap();

        assert_eq!(sync_run.status, SyncStatus::Completed);
        assert_eq!(sync_run.provider, "mock_sis");
        assert_eq!(sync_run.orgs_synced, 2);
        assert_eq!(sync_run.users_synced, 1);
        assert_eq!(sync_run.courses_synced, 1);
        assert_eq!(sync_run.classes_synced, 1);
        assert_eq!(sync_run.enrollments_synced, 1);
        assert!(sync_run.completed_at.is_some());
        assert!(sync_run.error_message.is_none());
    }

    #[tokio::test]
    async fn sync_engine_verifies_persisted_data() {
        let repo = setup_repo().await;
        let engine = SyncEngine::new(repo);

        let connector = MockConnector {
            payload: full_payload(),
            should_fail: false,
        };

        engine.run(&connector).await.unwrap();

        // Verify data was actually persisted by checking via the repo
        // We access it through the engine's repo
        let orgs = engine.repo.list_orgs().await.unwrap();
        assert_eq!(orgs.len(), 2);

        let sessions = engine.repo.list_academic_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);

        let users = engine
            .repo
            .list_users(&crate::models::sync::UserFilter::default())
            .await
            .unwrap();
        assert_eq!(users.len(), 1);

        let courses = engine.repo.list_courses().await.unwrap();
        assert_eq!(courses.len(), 1);

        let classes = engine.repo.list_classes().await.unwrap();
        assert_eq!(classes.len(), 1);

        let enrollments = engine.repo.list_enrollments().await.unwrap();
        assert_eq!(enrollments.len(), 1);

        let demographics = engine.repo.list_demographics().await.unwrap();
        assert_eq!(demographics.len(), 1);
    }

    #[tokio::test]
    async fn sync_engine_handles_connector_failure() {
        let repo = setup_repo().await;
        let engine = SyncEngine::new(repo);

        let connector = MockConnector {
            payload: SyncPayload::default(),
            should_fail: true,
        };

        let sync_run = engine.run(&connector).await.unwrap();

        assert_eq!(sync_run.status, SyncStatus::Failed);
        assert!(sync_run.error_message.is_some());
        assert!(sync_run
            .error_message
            .unwrap()
            .contains("Mock connector failure"));
    }

    #[tokio::test]
    async fn sync_engine_empty_payload() {
        let repo = setup_repo().await;
        let engine = SyncEngine::new(repo);

        let connector = MockConnector {
            payload: SyncPayload::default(),
            should_fail: false,
        };

        let sync_run = engine.run(&connector).await.unwrap();

        assert_eq!(sync_run.status, SyncStatus::Completed);
        assert_eq!(sync_run.orgs_synced, 0);
        assert_eq!(sync_run.users_synced, 0);
        assert_eq!(sync_run.courses_synced, 0);
        assert_eq!(sync_run.classes_synced, 0);
        assert_eq!(sync_run.enrollments_synced, 0);
    }

    #[tokio::test]
    async fn sync_engine_records_sync_run() {
        let repo = setup_repo().await;
        let engine = SyncEngine::new(repo);

        let connector = MockConnector {
            payload: full_payload(),
            should_fail: false,
        };

        let sync_run = engine.run(&connector).await.unwrap();

        // Verify we can retrieve the sync run from the DB
        let fetched = engine
            .repo
            .get_sync_run(sync_run.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.provider, "mock_sis");
        assert_eq!(fetched.status, SyncStatus::Completed);
        assert_eq!(fetched.orgs_synced, 2);
    }

    #[tokio::test]
    async fn sync_engine_latest_sync_run() {
        let repo = setup_repo().await;
        let engine = SyncEngine::new(repo);

        let connector = MockConnector {
            payload: full_payload(),
            should_fail: false,
        };

        let _run1 = engine.run(&connector).await.unwrap();
        let run2 = engine.run(&connector).await.unwrap();

        let latest = engine
            .repo
            .get_latest_sync_run("mock_sis")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.id, run2.id);
    }
}
