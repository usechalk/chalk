pub mod infinite_campus;
pub mod oneroster_client;
pub mod powerschool;
pub mod skyward;

use crate::error::Result;
use crate::models::{
    academic_session::AcademicSession, class::Class, course::Course, demographics::Demographics,
    enrollment::Enrollment, org::Org, user::User,
};
use async_trait::async_trait;

/// Payload containing all synced data from an SIS.
#[derive(Debug, Default)]
pub struct SyncPayload {
    pub orgs: Vec<Org>,
    pub academic_sessions: Vec<AcademicSession>,
    pub users: Vec<User>,
    pub courses: Vec<Course>,
    pub classes: Vec<Class>,
    pub enrollments: Vec<Enrollment>,
    pub demographics: Vec<Demographics>,
}

/// Trait for SIS connector implementations.
#[async_trait]
pub trait SisConnector: Send + Sync {
    async fn full_sync(&self) -> Result<SyncPayload>;
    async fn test_connection(&self) -> Result<()>;
    fn provider_name(&self) -> &str;
}
