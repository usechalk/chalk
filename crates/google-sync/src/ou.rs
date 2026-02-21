//! Organizational Unit management for Google Workspace.

use chalk_core::error::Result;

use crate::client::GoogleAdminClient;
use crate::models::GoogleOrgUnit;

/// Resolve an OU path template by replacing `{school}` and `{grade}` placeholders.
pub fn resolve_ou_path(template: &str, school_name: &str, grade: &str) -> String {
    template
        .replace("{school}", school_name)
        .replace("{grade}", grade)
}

/// Ensure an OU path exists in Google Workspace.
/// Creates it if not already present in `existing_ous`.
/// Returns `true` if a new OU was created.
pub async fn ensure_ou_exists(
    client: &GoogleAdminClient,
    ou_path: &str,
    existing_ous: &[String],
) -> Result<bool> {
    if existing_ous.contains(&ou_path.to_string()) {
        return Ok(false);
    }

    // Derive name and parent from the path
    let (parent, name) = split_ou_path(ou_path);

    let ou = GoogleOrgUnit {
        name: name.to_string(),
        org_unit_path: ou_path.to_string(),
        parent_org_unit_path: Some(parent.to_string()),
        org_unit_id: None,
    };

    client.create_org_unit(&ou).await?;
    Ok(true)
}

/// Split an OU path into (parent, name).
/// e.g. "/Students/HS/09" -> ("/Students/HS", "09")
fn split_ou_path(ou_path: &str) -> (&str, &str) {
    match ou_path.rfind('/') {
        Some(0) => ("/", &ou_path[1..]),
        Some(idx) => (&ou_path[..idx], &ou_path[idx + 1..]),
        None => ("/", ou_path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_template_with_school_and_grade() {
        let result = resolve_ou_path("/Students/{school}/{grade}", "Lincoln HS", "09");
        assert_eq!(result, "/Students/Lincoln HS/09");
    }

    #[test]
    fn resolve_template_school_only() {
        let result = resolve_ou_path("/Teachers/{school}", "Lincoln HS", "");
        assert_eq!(result, "/Teachers/Lincoln HS");
    }

    #[test]
    fn resolve_template_no_placeholders() {
        let result = resolve_ou_path("/Staff", "Lincoln HS", "09");
        assert_eq!(result, "/Staff");
    }

    #[test]
    fn resolve_template_multiple_occurrences() {
        let result = resolve_ou_path("/{school}/{school}", "Test", "09");
        assert_eq!(result, "/Test/Test");
    }

    #[test]
    fn split_ou_path_deep() {
        let (parent, name) = split_ou_path("/Students/HS/09");
        assert_eq!(parent, "/Students/HS");
        assert_eq!(name, "09");
    }

    #[test]
    fn split_ou_path_top_level() {
        let (parent, name) = split_ou_path("/Students");
        assert_eq!(parent, "/");
        assert_eq!(name, "Students");
    }

    #[test]
    fn split_ou_path_no_slash() {
        let (parent, name) = split_ou_path("Students");
        assert_eq!(parent, "/");
        assert_eq!(name, "Students");
    }

    #[tokio::test]
    async fn ensure_ou_exists_already_present() {
        // If OU already exists, should return false without API call
        let client = GoogleAdminClient::new("token", "C123").with_base_url("http://localhost:1"); // unreachable on purpose
        let existing = vec!["/Students".to_string(), "/Teachers".to_string()];
        let result = ensure_ou_exists(&client, "/Students", &existing)
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn ensure_ou_exists_creates_new() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = GoogleAdminClient::new("token", "C123").with_base_url(&server.uri());

        let response_body = serde_json::json!({
            "name": "09",
            "orgUnitPath": "/Students/HS/09",
            "parentOrgUnitPath": "/Students/HS",
            "orgUnitId": "ou-new"
        });

        Mock::given(method("POST"))
            .and(path("/admin/directory/v1/customer/C123/orgunits"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let existing = vec!["/Students".to_string()];
        let result = ensure_ou_exists(&client, "/Students/HS/09", &existing)
            .await
            .unwrap();
        assert!(result);
    }
}
