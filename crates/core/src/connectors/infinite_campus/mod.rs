pub mod mapper;

use async_trait::async_trait;
use tracing::info;

use crate::config::SisConfig;
use crate::connectors::oneroster_client::OneRosterClient;
use crate::connectors::powerschool::models::{
    AcademicSessionsResponse, ClassesResponse, CoursesResponse, DemographicsListResponse,
    EnrollmentsResponse, OrgsResponse, UsersResponse,
};
use crate::connectors::{SisConnector, SyncPayload};
use crate::error::{ChalkError, Result};

use self::mapper::InfiniteCampusMapper;

/// Infinite Campus SIS connector implementing the OneRoster 1.1 API.
pub struct InfiniteCampusConnector {
    client: OneRosterClient,
}

impl InfiniteCampusConnector {
    pub fn new(config: &SisConfig) -> Result<Self> {
        let token_url = config.token_url.as_ref().ok_or_else(|| {
            ChalkError::Config("token_url is required for Infinite Campus".into())
        })?;
        let client = OneRosterClient::new(
            &config.base_url,
            token_url,
            &config.client_id,
            &config.client_secret,
        );
        Ok(Self { client })
    }
}

#[async_trait]
impl SisConnector for InfiniteCampusConnector {
    async fn full_sync(&self) -> Result<SyncPayload> {
        info!("Starting full sync from Infinite Campus");
        self.client.authenticate().await?;

        info!("Fetching orgs");
        let orgs_response: Vec<OrgsResponse> = self.client.get_all("/orgs", "orgs").await?;
        let raw_orgs: Vec<_> = orgs_response.into_iter().flat_map(|r| r.orgs).collect();
        let orgs = InfiniteCampusMapper::normalize_orgs(raw_orgs);
        info!(count = orgs.len(), "Fetched orgs");

        info!("Fetching academic sessions");
        let sessions_response: Vec<AcademicSessionsResponse> = self
            .client
            .get_all("/academicSessions", "academicSessions")
            .await?;
        let raw_sessions: Vec<_> = sessions_response
            .into_iter()
            .flat_map(|r| r.academic_sessions)
            .collect();
        let academic_sessions = InfiniteCampusMapper::normalize_academic_sessions(raw_sessions);
        info!(count = academic_sessions.len(), "Fetched academic sessions");

        info!("Fetching users");
        let users_response: Vec<UsersResponse> = self.client.get_all("/users", "users").await?;
        let raw_users: Vec<_> = users_response.into_iter().flat_map(|r| r.users).collect();
        let users = InfiniteCampusMapper::normalize_users(raw_users);
        info!(count = users.len(), "Fetched users");

        info!("Fetching courses");
        let courses_response: Vec<CoursesResponse> =
            self.client.get_all("/courses", "courses").await?;
        let raw_courses: Vec<_> = courses_response
            .into_iter()
            .flat_map(|r| r.courses)
            .collect();
        let courses = InfiniteCampusMapper::normalize_courses(raw_courses);
        info!(count = courses.len(), "Fetched courses");

        info!("Fetching classes");
        let classes_response: Vec<ClassesResponse> =
            self.client.get_all("/classes", "classes").await?;
        let raw_classes: Vec<_> = classes_response
            .into_iter()
            .flat_map(|r| r.classes)
            .collect();
        let classes = InfiniteCampusMapper::normalize_classes(raw_classes);
        info!(count = classes.len(), "Fetched classes");

        info!("Fetching enrollments");
        let enrollments_response: Vec<EnrollmentsResponse> =
            self.client.get_all("/enrollments", "enrollments").await?;
        let raw_enrollments: Vec<_> = enrollments_response
            .into_iter()
            .flat_map(|r| r.enrollments)
            .collect();
        let enrollments = InfiniteCampusMapper::normalize_enrollments(raw_enrollments);
        info!(count = enrollments.len(), "Fetched enrollments");

        info!("Fetching demographics");
        let demographics_response: Vec<DemographicsListResponse> =
            self.client.get_all("/demographics", "demographics").await?;
        let raw_demographics: Vec<_> = demographics_response
            .into_iter()
            .flat_map(|r| r.demographics)
            .collect();
        let demographics = InfiniteCampusMapper::normalize_demographics(raw_demographics);
        info!(count = demographics.len(), "Fetched demographics");

        info!("Full sync from Infinite Campus completed successfully");

        Ok(SyncPayload {
            orgs,
            academic_sessions,
            users,
            courses,
            classes,
            enrollments,
            demographics,
        })
    }

    async fn test_connection(&self) -> Result<()> {
        info!("Testing Infinite Campus connection");
        self.client.test_connection().await?;
        info!("Infinite Campus connection test successful");
        Ok(())
    }

    fn provider_name(&self) -> &str {
        "infinite_campus"
    }
}
