pub mod mapper;
pub mod models;

use async_trait::async_trait;
use tracing::info;

use crate::config::SisConfig;
use crate::connectors::oneroster_client::OneRosterClient;
use crate::connectors::{SisConnector, SyncPayload};
use crate::error::Result;

use self::mapper::PowerSchoolMapper;
use self::models::{
    AcademicSessionsResponse, ClassesResponse, CoursesResponse, DemographicsListResponse,
    EnrollmentsResponse, OrgsResponse, UsersResponse,
};

/// PowerSchool SIS connector implementing the OneRoster 1.1 API.
pub struct PowerSchoolConnector {
    client: OneRosterClient,
}

impl PowerSchoolConnector {
    pub fn new(config: &SisConfig) -> Self {
        let token_url = format!("{}/oauth/access_token", config.base_url);
        let api_base = format!("{}/api/ims/oneroster/v1p1", config.base_url);
        let client = OneRosterClient::new(
            &api_base,
            &token_url,
            &config.client_id,
            &config.client_secret,
        );
        Self { client }
    }

    /// Create from a pre-built client (useful for testing).
    pub fn from_client(client: OneRosterClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl SisConnector for PowerSchoolConnector {
    async fn full_sync(&self) -> Result<SyncPayload> {
        info!("Starting full sync from PowerSchool");

        self.client.authenticate().await?;

        info!("Fetching orgs");
        let orgs_response: Vec<OrgsResponse> = self.client.get_all("/orgs", "orgs").await?;
        let raw_orgs: Vec<_> = orgs_response.into_iter().flat_map(|r| r.orgs).collect();
        let orgs = PowerSchoolMapper::normalize_orgs(raw_orgs);
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
        let academic_sessions = PowerSchoolMapper::normalize_academic_sessions(raw_sessions);
        info!(count = academic_sessions.len(), "Fetched academic sessions");

        info!("Fetching users");
        let users_response: Vec<UsersResponse> = self.client.get_all("/users", "users").await?;
        let raw_users: Vec<_> = users_response.into_iter().flat_map(|r| r.users).collect();
        let users = PowerSchoolMapper::normalize_users(raw_users);
        info!(count = users.len(), "Fetched users");

        info!("Fetching courses");
        let courses_response: Vec<CoursesResponse> =
            self.client.get_all("/courses", "courses").await?;
        let raw_courses: Vec<_> = courses_response
            .into_iter()
            .flat_map(|r| r.courses)
            .collect();
        let courses = PowerSchoolMapper::normalize_courses(raw_courses);
        info!(count = courses.len(), "Fetched courses");

        info!("Fetching classes");
        let classes_response: Vec<ClassesResponse> =
            self.client.get_all("/classes", "classes").await?;
        let raw_classes: Vec<_> = classes_response
            .into_iter()
            .flat_map(|r| r.classes)
            .collect();
        let classes = PowerSchoolMapper::normalize_classes(raw_classes);
        info!(count = classes.len(), "Fetched classes");

        info!("Fetching enrollments");
        let enrollments_response: Vec<EnrollmentsResponse> =
            self.client.get_all("/enrollments", "enrollments").await?;
        let raw_enrollments: Vec<_> = enrollments_response
            .into_iter()
            .flat_map(|r| r.enrollments)
            .collect();
        let enrollments = PowerSchoolMapper::normalize_enrollments(raw_enrollments);
        info!(count = enrollments.len(), "Fetched enrollments");

        info!("Fetching demographics");
        let demographics_response: Vec<DemographicsListResponse> =
            self.client.get_all("/demographics", "demographics").await?;
        let raw_demographics: Vec<_> = demographics_response
            .into_iter()
            .flat_map(|r| r.demographics)
            .collect();
        let demographics = PowerSchoolMapper::normalize_demographics(raw_demographics);
        info!(count = demographics.len(), "Fetched demographics");

        info!("Full sync completed successfully");

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
        info!("Testing PowerSchool connection");
        self.client.test_connection().await?;
        info!("PowerSchool connection test successful");
        Ok(())
    }

    fn provider_name(&self) -> &str {
        "powerschool"
    }
}
