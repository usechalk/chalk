//! Platform migration support for Clever and ClassLink.
//!
//! Provides parsing of Clever and ClassLink export directories into a unified
//! `MigrationPlan` that contains roster data, app configurations, and cutover steps.

pub mod classlink;
pub mod clever;

use serde::{Deserialize, Serialize};

use crate::connectors::SyncPayload;

/// The source platform being migrated from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MigrationSource {
    Clever,
    ClassLink,
}

impl std::fmt::Display for MigrationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationSource::Clever => write!(f, "Clever"),
            MigrationSource::ClassLink => write!(f, "ClassLink"),
        }
    }
}

/// Configuration for an application that was connected to the source platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    /// Name of the application.
    pub app_name: String,
    /// SSO type (e.g., "saml", "oauth2", "oidc").
    pub sso_type: String,
    /// Redirect URIs configured for the app.
    pub redirect_uris: Vec<String>,
    /// Data scopes the app had access to.
    pub data_scopes: Vec<String>,
}

/// A single step in the cutover checklist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStep {
    /// Human-readable description of the step.
    pub description: String,
    /// Whether this step has been completed.
    pub completed: bool,
}

/// A complete migration plan parsed from an export directory.
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// The source platform.
    pub source: MigrationSource,
    /// Roster data parsed from OneRoster CSV files.
    #[serde(skip)]
    pub roster_data: SyncPayload,
    /// Application configurations found in the export.
    pub app_configs: Vec<AppConfig>,
    /// Cutover checklist steps.
    pub cutover_steps: Vec<MigrationStep>,
}

impl MigrationPlan {
    /// Returns a summary of the roster data counts.
    pub fn roster_summary(&self) -> RosterSummary {
        RosterSummary {
            orgs: self.roster_data.orgs.len(),
            academic_sessions: self.roster_data.academic_sessions.len(),
            users: self.roster_data.users.len(),
            courses: self.roster_data.courses.len(),
            classes: self.roster_data.classes.len(),
            enrollments: self.roster_data.enrollments.len(),
            demographics: self.roster_data.demographics.len(),
        }
    }
}

/// Summary counts of roster data in a migration plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterSummary {
    pub orgs: usize,
    pub academic_sessions: usize,
    pub users: usize,
    pub courses: usize,
    pub classes: usize,
    pub enrollments: usize,
    pub demographics: usize,
}

/// Generate the standard cutover steps for a given platform.
fn generate_cutover_steps(source: &MigrationSource) -> Vec<MigrationStep> {
    let platform_name = source.to_string();
    vec![
        MigrationStep {
            description: format!("Export roster data from {platform_name}"),
            completed: true, // Already done if we have the data
        },
        MigrationStep {
            description: "Review imported roster data for accuracy".to_string(),
            completed: false,
        },
        MigrationStep {
            description: "Persist roster data to Chalk database".to_string(),
            completed: false,
        },
        MigrationStep {
            description: "Reconfigure application SSO settings in Chalk IDP".to_string(),
            completed: false,
        },
        MigrationStep {
            description: "Update DNS/redirect URIs to point to Chalk".to_string(),
            completed: false,
        },
        MigrationStep {
            description: "Test SSO login with a sample user".to_string(),
            completed: false,
        },
        MigrationStep {
            description: format!("Disable {platform_name} sync/rostering"),
            completed: false,
        },
        MigrationStep {
            description: "Enable Chalk SIS sync schedule".to_string(),
            completed: false,
        },
        MigrationStep {
            description: "Notify staff and verify production access".to_string(),
            completed: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_source_display() {
        assert_eq!(MigrationSource::Clever.to_string(), "Clever");
        assert_eq!(MigrationSource::ClassLink.to_string(), "ClassLink");
    }

    #[test]
    fn migration_source_serialize() {
        let clever = serde_json::to_string(&MigrationSource::Clever).unwrap();
        assert_eq!(clever, "\"clever\"");
        let classlink = serde_json::to_string(&MigrationSource::ClassLink).unwrap();
        assert_eq!(classlink, "\"classlink\"");
    }

    #[test]
    fn migration_source_deserialize() {
        let clever: MigrationSource = serde_json::from_str("\"clever\"").unwrap();
        assert_eq!(clever, MigrationSource::Clever);
        let classlink: MigrationSource = serde_json::from_str("\"classlink\"").unwrap();
        assert_eq!(classlink, MigrationSource::ClassLink);
    }

    #[test]
    fn app_config_roundtrip() {
        let config = AppConfig {
            app_name: "Canvas LMS".to_string(),
            sso_type: "saml".to_string(),
            redirect_uris: vec!["https://canvas.example.com/saml".to_string()],
            data_scopes: vec!["roster".to_string(), "grades".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn migration_step_roundtrip() {
        let step = MigrationStep {
            description: "Test step".to_string(),
            completed: false,
        };
        let json = serde_json::to_string(&step).unwrap();
        let parsed: MigrationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, step);
    }

    #[test]
    fn migration_plan_roster_summary() {
        let plan = MigrationPlan {
            source: MigrationSource::Clever,
            roster_data: SyncPayload::default(),
            app_configs: vec![],
            cutover_steps: vec![],
        };
        let summary = plan.roster_summary();
        assert_eq!(summary.orgs, 0);
        assert_eq!(summary.users, 0);
        assert_eq!(summary.courses, 0);
        assert_eq!(summary.classes, 0);
        assert_eq!(summary.enrollments, 0);
        assert_eq!(summary.academic_sessions, 0);
        assert_eq!(summary.demographics, 0);
    }

    #[test]
    fn roster_summary_serialize() {
        let summary = RosterSummary {
            orgs: 2,
            academic_sessions: 3,
            users: 100,
            courses: 10,
            classes: 25,
            enrollments: 500,
            demographics: 100,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: RosterSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, summary);
    }

    #[test]
    fn generate_cutover_steps_clever() {
        let steps = generate_cutover_steps(&MigrationSource::Clever);
        assert!(steps.len() >= 8);
        assert!(steps[0].completed); // Export step is pre-completed
        assert!(!steps[1].completed);
        assert!(steps[0].description.contains("Clever"));
    }

    #[test]
    fn generate_cutover_steps_classlink() {
        let steps = generate_cutover_steps(&MigrationSource::ClassLink);
        assert!(steps.len() >= 8);
        assert!(steps[0].description.contains("ClassLink"));
        assert!(steps
            .iter()
            .any(|s| s.description.contains("Disable ClassLink")));
    }
}
