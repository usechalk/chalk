//! Clever migration support — parses a Clever export directory into a `MigrationPlan`.

use std::path::Path;

use crate::error::{ChalkError, Result};
use crate::oneroster_csv::read_oneroster_csv;

use super::{generate_cutover_steps, AppConfig, MigrationPlan, MigrationSource};

/// Parse a Clever export directory into a `MigrationPlan`.
///
/// Expects the directory to contain OneRoster CSV files (orgs.csv, users.csv, etc.)
/// and optionally an `apps.json` file with application configuration data.
pub fn parse_clever_export(path: &Path) -> Result<MigrationPlan> {
    if !path.is_dir() {
        return Err(ChalkError::PlatformMigration(format!(
            "Clever export directory not found: {}",
            path.display()
        )));
    }

    let roster_data = read_oneroster_csv(path)?;

    let app_configs = load_apps_json(path)?;

    let cutover_steps = generate_cutover_steps(&MigrationSource::Clever);

    Ok(MigrationPlan {
        source: MigrationSource::Clever,
        roster_data,
        app_configs,
        cutover_steps,
    })
}

/// Load application configs from `apps.json` if present.
fn load_apps_json(dir: &Path) -> Result<Vec<AppConfig>> {
    let apps_path = dir.join("apps.json");
    if !apps_path.exists() {
        return Ok(vec![]);
    }

    let data = std::fs::read_to_string(&apps_path)?;
    let configs: Vec<AppConfig> = serde_json::from_str(&data)
        .map_err(|e| ChalkError::PlatformMigration(format!("Failed to parse apps.json: {e}")))?;

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::SyncPayload;
    use crate::models::common::{OrgType, Status};
    use crate::models::org::Org;
    use crate::oneroster_csv::write_oneroster_csv;
    use chrono::{TimeZone, Utc};

    fn sample_datetime() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap()
    }

    fn sample_org() -> Org {
        Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: sample_datetime(),
            metadata: None,
            name: "Springfield District".to_string(),
            org_type: OrgType::District,
            identifier: Some("SSD001".to_string()),
            parent: None,
            children: vec![],
        }
    }

    #[test]
    fn parse_clever_export_nonexistent_dir() {
        let result = parse_clever_export(Path::new("/nonexistent/clever/export"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn parse_clever_export_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let plan = parse_clever_export(dir.path()).unwrap();
        assert_eq!(plan.source, MigrationSource::Clever);
        assert!(plan.roster_data.orgs.is_empty());
        assert!(plan.roster_data.users.is_empty());
        assert!(plan.app_configs.is_empty());
        assert!(!plan.cutover_steps.is_empty());
    }

    #[test]
    fn parse_clever_export_with_csv_data() {
        let dir = tempfile::tempdir().unwrap();
        let payload = SyncPayload {
            orgs: vec![sample_org()],
            ..Default::default()
        };
        write_oneroster_csv(&payload, dir.path()).unwrap();

        let plan = parse_clever_export(dir.path()).unwrap();
        assert_eq!(plan.source, MigrationSource::Clever);
        assert_eq!(plan.roster_data.orgs.len(), 1);
        assert_eq!(plan.roster_data.orgs[0].sourced_id, "org-001");
    }

    #[test]
    fn parse_clever_export_with_apps_json() {
        let dir = tempfile::tempdir().unwrap();

        // Write minimal CSV data
        let payload = SyncPayload {
            orgs: vec![sample_org()],
            ..Default::default()
        };
        write_oneroster_csv(&payload, dir.path()).unwrap();

        // Write apps.json
        let apps = vec![
            AppConfig {
                app_name: "Canvas LMS".to_string(),
                sso_type: "saml".to_string(),
                redirect_uris: vec!["https://canvas.example.com/saml/consume".to_string()],
                data_scopes: vec!["roster".to_string()],
            },
            AppConfig {
                app_name: "Google Classroom".to_string(),
                sso_type: "oauth2".to_string(),
                redirect_uris: vec!["https://classroom.google.com/callback".to_string()],
                data_scopes: vec!["roster".to_string(), "grades".to_string()],
            },
        ];
        let json = serde_json::to_string_pretty(&apps).unwrap();
        std::fs::write(dir.path().join("apps.json"), json).unwrap();

        let plan = parse_clever_export(dir.path()).unwrap();
        assert_eq!(plan.app_configs.len(), 2);
        assert_eq!(plan.app_configs[0].app_name, "Canvas LMS");
        assert_eq!(plan.app_configs[0].sso_type, "saml");
        assert_eq!(plan.app_configs[1].app_name, "Google Classroom");
        assert_eq!(plan.app_configs[1].data_scopes.len(), 2);
    }

    #[test]
    fn parse_clever_export_invalid_apps_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("apps.json"), "not valid json").unwrap();

        let result = parse_clever_export(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("apps.json"));
    }

    #[test]
    fn parse_clever_export_has_cutover_steps() {
        let dir = tempfile::tempdir().unwrap();
        let plan = parse_clever_export(dir.path()).unwrap();
        assert!(!plan.cutover_steps.is_empty());
        assert!(plan.cutover_steps[0].completed); // Export step
        assert!(plan.cutover_steps[0].description.contains("Clever"));
    }

    #[test]
    fn parse_clever_export_roster_summary() {
        let dir = tempfile::tempdir().unwrap();
        let payload = SyncPayload {
            orgs: vec![sample_org()],
            ..Default::default()
        };
        write_oneroster_csv(&payload, dir.path()).unwrap();

        let plan = parse_clever_export(dir.path()).unwrap();
        let summary = plan.roster_summary();
        assert_eq!(summary.orgs, 1);
        assert_eq!(summary.users, 0);
        assert_eq!(summary.courses, 0);
    }

    #[test]
    fn load_apps_json_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_apps_json(dir.path()).unwrap();
        assert!(result.is_empty());
    }
}
