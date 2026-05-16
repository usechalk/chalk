//! OneRoster CSV connector — reads a OneRoster 1.1 CSV bundle from a local
//! directory and exposes it through the standard `SisConnector` trait.
//!
//! Lets districts feed chalk from any vendor that emits a OneRoster CSV
//! export (most do — it's the spec's interchange format), or from
//! hand-curated bundles for testing. Pair with `[sis] provider =
//! "oneroster_csv"` and `csv_dir = "/path/to/bundle"`.

use std::path::PathBuf;

use async_trait::async_trait;
use tracing::info;

use crate::config::SisConfig;
use crate::connectors::{SisConnector, SyncPayload};
use crate::error::{ChalkError, Result};
use crate::oneroster_csv::read_oneroster_csv;

const PROVIDER_NAME: &str = "oneroster_csv";

/// Filesystem-backed SIS connector that reads OneRoster 1.1 CSV files.
#[derive(Debug, Clone)]
pub struct OneRosterCsvConnector {
    csv_dir: PathBuf,
}

impl OneRosterCsvConnector {
    /// Construct from `SisConfig`. Returns an error if `csv_dir` is unset —
    /// the config validator catches this earlier, but we don't want to
    /// silently no-op if a caller bypassed validation.
    pub fn new(config: &SisConfig) -> Result<Self> {
        let csv_dir = config.csv_dir.as_deref().ok_or_else(|| {
            ChalkError::Config("sis.csv_dir is required for the oneroster_csv connector".into())
        })?;
        Ok(Self {
            csv_dir: PathBuf::from(csv_dir),
        })
    }

    /// Construct directly from a directory path (test helper).
    pub fn from_path(csv_dir: PathBuf) -> Self {
        Self { csv_dir }
    }
}

#[async_trait]
impl SisConnector for OneRosterCsvConnector {
    async fn full_sync(&self) -> Result<SyncPayload> {
        info!(dir = %self.csv_dir.display(), "Starting full sync from OneRoster CSV");
        // The reader is synchronous and CPU/IO bound rather than network bound;
        // run it on the blocking pool so we don't stall the tokio scheduler on
        // a large bundle. Cloning the path keeps the move closure 'static.
        let dir = self.csv_dir.clone();
        let payload = tokio::task::spawn_blocking(move || read_oneroster_csv(&dir))
            .await
            .map_err(|e| ChalkError::Sync(format!("csv read task panicked: {e}")))??;
        info!(
            orgs = payload.orgs.len(),
            users = payload.users.len(),
            classes = payload.classes.len(),
            enrollments = payload.enrollments.len(),
            "OneRoster CSV sync completed"
        );
        Ok(payload)
    }

    async fn test_connection(&self) -> Result<()> {
        // The "connection" is the filesystem. Verify the configured directory
        // exists and is readable; reading the bundle itself is left to
        // full_sync since it can be expensive.
        if !self.csv_dir.exists() {
            return Err(ChalkError::Sync(format!(
                "csv_dir does not exist: {}",
                self.csv_dir.display()
            )));
        }
        if !self.csv_dir.is_dir() {
            return Err(ChalkError::Sync(format!(
                "csv_dir is not a directory: {}",
                self.csv_dir.display()
            )));
        }
        Ok(())
    }

    fn provider_name(&self) -> &str {
        PROVIDER_NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        common::{OrgType, RoleType, Status},
        org::Org,
        user::User,
    };
    use crate::oneroster_csv::write_oneroster_csv;
    use chrono::Utc;
    use tempfile::TempDir;

    fn make_payload() -> SyncPayload {
        SyncPayload {
            orgs: vec![Org {
                sourced_id: "org-1".into(),
                status: Status::Active,
                date_last_modified: Utc::now(),
                metadata: None,
                name: "Test School".into(),
                org_type: OrgType::School,
                identifier: None,
                parent: None,
                children: vec![],
            }],
            users: vec![User {
                sourced_id: "user-1".into(),
                status: Status::Active,
                date_last_modified: Utc::now(),
                metadata: None,
                username: "jdoe".into(),
                user_ids: vec![],
                enabled_user: true,
                given_name: "Jane".into(),
                family_name: "Doe".into(),
                middle_name: None,
                role: RoleType::Student,
                identifier: None,
                email: Some("jane@example.com".into()),
                sms: None,
                phone: None,
                agents: vec![],
                orgs: vec!["org-1".into()],
                grades: vec!["10".into()],
            }],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn full_sync_reads_bundle() {
        let dir = TempDir::new().unwrap();
        write_oneroster_csv(&make_payload(), dir.path()).unwrap();

        let connector = OneRosterCsvConnector::from_path(dir.path().to_path_buf());
        connector.test_connection().await.unwrap();
        let payload = connector.full_sync().await.unwrap();

        assert_eq!(payload.orgs.len(), 1);
        assert_eq!(payload.users.len(), 1);
        assert_eq!(payload.users[0].sourced_id, "user-1");
    }

    #[tokio::test]
    async fn test_connection_rejects_missing_dir() {
        let connector = OneRosterCsvConnector::from_path(PathBuf::from("/definitely/not/here"));
        let err = connector.test_connection().await.unwrap_err();
        assert!(
            matches!(err, ChalkError::Sync(msg) if msg.contains("does not exist")),
            "expected 'does not exist' connector error"
        );
    }

    #[tokio::test]
    async fn test_connection_rejects_file_target() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("not-a-dir.csv");
        std::fs::write(&file, "x").unwrap();
        let connector = OneRosterCsvConnector::from_path(file);
        let err = connector.test_connection().await.unwrap_err();
        assert!(matches!(err, ChalkError::Sync(msg) if msg.contains("not a directory")));
    }

    #[test]
    fn new_requires_csv_dir() {
        let cfg = SisConfig::default();
        let err = OneRosterCsvConnector::new(&cfg).unwrap_err();
        assert!(matches!(err, ChalkError::Config(msg) if msg.contains("csv_dir")));
    }

    #[test]
    fn provider_name_is_stable() {
        let connector = OneRosterCsvConnector::from_path(PathBuf::from("."));
        assert_eq!(connector.provider_name(), PROVIDER_NAME);
    }
}
