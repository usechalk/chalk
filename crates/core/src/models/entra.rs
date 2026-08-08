//! Entra ID (Azure AD) provisioning models — the Graph-API sibling of
//! [`super::ad_sync`], deliberately the same shape so the two directory
//! syncs share their operational vocabulary.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Status of a user's Entra sync state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntraSyncStatus {
    Pending,
    Synced,
    Error,
    Disabled,
}

impl EntraSyncStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntraSyncStatus::Pending => "pending",
            EntraSyncStatus::Synced => "synced",
            EntraSyncStatus::Error => "error",
            EntraSyncStatus::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "synced" => EntraSyncStatus::Synced,
            "error" => EntraSyncStatus::Error,
            "disabled" => EntraSyncStatus::Disabled,
            _ => EntraSyncStatus::Pending,
        }
    }
}

/// Per-user Entra provisioning state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntraUserState {
    pub user_sourced_id: String,
    /// The Graph `id` of the provisioned account — the durable identity;
    /// UPNs can be renamed under it.
    pub entra_object_id: String,
    pub upn: String,
    pub field_hash: String,
    pub sync_status: EntraSyncStatus,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Status of an Entra sync run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntraRunStatus {
    Running,
    Completed,
    Failed,
}

impl EntraRunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntraRunStatus::Running => "running",
            EntraRunStatus::Completed => "completed",
            EntraRunStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "completed" => EntraRunStatus::Completed,
            "failed" => EntraRunStatus::Failed,
            _ => EntraRunStatus::Running,
        }
    }
}

/// One Entra sync run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntraSyncRun {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: EntraRunStatus,
    pub users_created: i64,
    pub users_updated: i64,
    pub users_disabled: i64,
    pub users_skipped: i64,
    pub errors: i64,
    pub error_details: Option<String>,
    pub dry_run: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_round_trip_and_unknowns_default_safely() {
        for s in [
            EntraSyncStatus::Pending,
            EntraSyncStatus::Synced,
            EntraSyncStatus::Error,
            EntraSyncStatus::Disabled,
        ] {
            assert_eq!(EntraSyncStatus::parse(s.as_str()), s);
        }
        assert_eq!(
            EntraSyncStatus::parse("garbage"),
            EntraSyncStatus::Pending,
            "an unknown state means nothing has been proven done"
        );
        for s in [
            EntraRunStatus::Running,
            EntraRunStatus::Completed,
            EntraRunStatus::Failed,
        ] {
            assert_eq!(EntraRunStatus::parse(s.as_str()), s);
        }
        assert_eq!(EntraRunStatus::parse("garbage"), EntraRunStatus::Running);
    }
}
