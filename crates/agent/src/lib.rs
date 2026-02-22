//! Chalk Agent — AI-powered sync diagnostics and configuration assistance.
//!
//! This crate defines the trait boundary for the agent system. The actual LLM
//! integration will be added when remix-agent-runtime is integrated in a future phase.
//! It also provides static guidance methods for SAML and Google Sync setup.

use chalk_core::config::ChalkConfig;

/// Trait for agent services that can diagnose sync issues and suggest configurations.
pub trait AgentService: Send + Sync {
    /// Analyze a sync failure and provide diagnostic information.
    fn diagnose_sync_failure(&self, error: &str, provider: &str) -> AgentResponse;

    /// Suggest configuration for a given SIS provider.
    fn suggest_config(&self, provider: &str) -> AgentResponse;
}

/// Response from the agent service.
#[derive(Debug, Clone)]
pub struct AgentResponse {
    /// Human-readable message describing the diagnosis or suggestion.
    pub message: String,
    /// Optional suggested action the user could take.
    pub suggested_action: Option<String>,
}

/// Returns whether the agent feature is enabled.
///
/// Currently always returns false. Will return true once an LLM API key
/// is configured and the agent runtime is integrated.
pub fn is_enabled() -> bool {
    false
}

/// Return step-by-step text instructions for configuring SAML SSO with Google Workspace.
///
/// The `workspace_domain` is used to customize the instructions with the
/// district's actual domain (e.g. "springfield.k12.us").
pub fn guide_saml_setup(workspace_domain: &str) -> String {
    format!(
        r#"SAML SSO Setup Guide for Google Workspace ({domain})
=====================================================

Prerequisites:
- Chalk IDP must be enabled (idp.enabled = true in chalk.toml)
- A publicly accessible URL for your Chalk instance (chalk.public_url)
- SAML certificate and key generated (created during `chalk init`)

Steps:

1. Log in to Google Admin Console
   - Navigate to https://admin.google.com
   - Sign in with a super administrator account for {domain}

2. Navigate to SSO Settings
   - Go to Security > Authentication > SSO with third-party IdP
   - Click "Add SSO profile" or "Set up SSO with third-party identity provider"

3. Configure the SSO Profile
   - Check "Set up SSO with third-party identity provider"
   - Sign-in page URL: https://{{your-chalk-public-url}}/idp/login
   - Sign-out page URL: https://{{your-chalk-public-url}}/idp/logout
   - Change password URL: https://{{your-chalk-public-url}}/idp/change-password

4. Upload the SAML Certificate
   - Click "Upload certificate"
   - Upload the file at your configured saml_cert_path (e.g., saml_cert.pem)

5. Configure Chalk IDP (chalk.toml)
   - Set [idp.google] section:
     workspace_domain = "{domain}"
     google_acs_url = "https://accounts.google.com/samlrp/acs"
     google_entity_id = "google.com"

6. Set the Entity ID
   - In Google Admin, set Entity ID to: https://{{your-chalk-public-url}}/idp/saml/metadata

7. Verify the SAML Metadata
   - Visit https://{{your-chalk-public-url}}/idp/saml/metadata
   - Confirm it returns valid XML with your certificate

8. Test the Integration
   - Use Google's "Test SAML SSO" feature in the Admin Console
   - Or navigate to a Google service while signed out to trigger SSO

9. Roll Out
   - Once testing succeeds, enable SSO for the appropriate organizational units
   - Start with a test OU before enabling district-wide
"#,
        domain = workspace_domain
    )
}

/// Return setup instructions for configuring Google Workspace sync.
pub fn guide_google_sync_setup() -> String {
    r#"Google Workspace Sync Setup Guide
==================================

Prerequisites:
- A Google Workspace domain with admin access
- A Google Cloud project with Admin SDK API enabled

Steps:

1. Create a Service Account
   - Go to https://console.cloud.google.com
   - Navigate to IAM & Admin > Service Accounts
   - Create a new service account (e.g., "chalk-sync")
   - Create a JSON key and download it

2. Enable Domain-Wide Delegation
   - In the service account settings, enable "Domain-wide delegation"
   - Note the Client ID (numeric)

3. Authorize the Service Account in Google Admin
   - Go to https://admin.google.com
   - Navigate to Security > API Controls > Domain-wide delegation
   - Click "Add new"
   - Enter the Client ID from step 2
   - Add the following OAuth scopes:
     - https://www.googleapis.com/auth/admin.directory.user
     - https://www.googleapis.com/auth/admin.directory.orgunit

4. Configure Chalk (chalk.toml)
   - Set [google_sync] section:
     enabled = true
     provision_users = true
     manage_ous = true
     suspend_inactive = true
     service_account_key_path = "/path/to/service-account-key.json"
     admin_email = "admin@yourdomain.com"
     workspace_domain = "yourdomain.com"

5. Configure OU Mapping (optional)
   - Set [google_sync.ou_mapping]:
     students = "/Students/{school}/{grade}"
     teachers = "/Teachers/{school}"
     staff = "/Staff/{school}"

6. Test with Dry Run
   - Run: chalk google-sync --dry-run
   - Review the output to confirm expected changes

7. Execute the Sync
   - Run: chalk google-sync
   - Monitor the output for any errors

8. Set Up Scheduled Sync (optional)
   - Configure sync_schedule in chalk.toml (cron syntax)
   - Default: "0 3 * * *" (daily at 3 AM)
"#
    .to_string()
}

/// Validate SAML-related configuration and return a list of warnings or errors.
///
/// Returns an empty vector if everything looks correct.
pub fn validate_saml_config(config: &ChalkConfig) -> Vec<String> {
    let mut issues = Vec::new();

    if !config.idp.enabled {
        issues.push("IDP is not enabled (idp.enabled = false)".to_string());
        return issues;
    }

    if config.chalk.public_url.is_none() {
        issues.push("chalk.public_url is required for SAML but not set".to_string());
    }

    if config.idp.saml_cert_path.is_none() {
        issues.push("idp.saml_cert_path is not configured".to_string());
    } else if let Some(ref cert_path) = config.idp.saml_cert_path {
        if !std::path::Path::new(cert_path).exists() {
            issues.push(format!("SAML certificate file not found: {}", cert_path));
        }
    }

    if config.idp.saml_key_path.is_none() {
        issues.push("idp.saml_key_path is not configured".to_string());
    } else if let Some(ref key_path) = config.idp.saml_key_path {
        if !std::path::Path::new(key_path).exists() {
            issues.push(format!("SAML private key file not found: {}", key_path));
        }
    }

    if config.idp.google.is_none() {
        issues.push(
            "idp.google section is not configured (required for Google Workspace SSO)".to_string(),
        );
    } else if let Some(ref google) = config.idp.google {
        if google.workspace_domain.is_empty() {
            issues.push("idp.google.workspace_domain is empty".to_string());
        }
        if google.google_acs_url.is_empty() {
            issues.push("idp.google.google_acs_url is empty".to_string());
        }
        if google.google_entity_id.is_empty() {
            issues.push("idp.google.google_entity_id is empty".to_string());
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use chalk_core::config::{
        ChalkConfig, ChalkSection, DatabaseConfig, IdpConfig, IdpGoogleConfig, SisConfig,
    };

    struct MockAgent;

    impl AgentService for MockAgent {
        fn diagnose_sync_failure(&self, error: &str, provider: &str) -> AgentResponse {
            AgentResponse {
                message: format!("Diagnosed error '{error}' for provider '{provider}'"),
                suggested_action: Some("Check credentials".to_string()),
            }
        }

        fn suggest_config(&self, provider: &str) -> AgentResponse {
            AgentResponse {
                message: format!("Config suggestion for {provider}"),
                suggested_action: None,
            }
        }
    }

    #[test]
    fn agent_not_enabled() {
        assert!(!is_enabled());
    }

    #[test]
    fn mock_agent_diagnose() {
        let agent = MockAgent;
        let response = agent.diagnose_sync_failure("timeout", "powerschool");
        assert!(response.message.contains("timeout"));
        assert!(response.message.contains("powerschool"));
        assert!(response.suggested_action.is_some());
    }

    #[test]
    fn mock_agent_suggest_config() {
        let agent = MockAgent;
        let response = agent.suggest_config("infinite_campus");
        assert!(response.message.contains("infinite_campus"));
        assert!(response.suggested_action.is_none());
    }

    #[test]
    fn agent_response_clone() {
        let response = AgentResponse {
            message: "test".to_string(),
            suggested_action: Some("action".to_string()),
        };
        let cloned = response.clone();
        assert_eq!(cloned.message, "test");
        assert_eq!(cloned.suggested_action.as_deref(), Some("action"));
    }

    #[test]
    fn guide_saml_setup_returns_nonempty() {
        let guide = guide_saml_setup("springfield.k12.us");
        assert!(!guide.is_empty());
        assert!(guide.contains("springfield.k12.us"));
        assert!(guide.contains("Google Admin Console"));
        assert!(guide.contains("SAML"));
        assert!(guide.contains("saml_cert"));
    }

    #[test]
    fn guide_saml_setup_includes_domain() {
        let guide = guide_saml_setup("example.edu");
        assert!(guide.contains("example.edu"));
    }

    #[test]
    fn guide_google_sync_setup_returns_nonempty() {
        let guide = guide_google_sync_setup();
        assert!(!guide.is_empty());
        assert!(guide.contains("Service Account"));
        assert!(
            guide.contains("Domain-Wide Delegation") || guide.contains("Domain-wide delegation")
        );
        assert!(guide.contains("google-sync"));
        assert!(guide.contains("dry-run"));
    }

    fn make_test_config() -> ChalkConfig {
        ChalkConfig {
            chalk: ChalkSection {
                instance_name: "Test".into(),
                data_dir: "/tmp".into(),
                public_url: Some("https://chalk.example.com".into()),
                database: DatabaseConfig::default(),
                telemetry: Default::default(),
                admin_password_hash: None,
            },
            sis: SisConfig::default(),
            idp: IdpConfig {
                enabled: true,
                qr_badge_login: false,
                picture_passwords: false,
                saml_cert_path: Some("/nonexistent/cert.pem".into()),
                saml_key_path: Some("/nonexistent/key.pem".into()),
                session_timeout_minutes: 480,
                default_password_pattern: None,
                default_password_roles: vec![],
                google: Some(IdpGoogleConfig {
                    workspace_domain: "example.com".into(),
                    google_acs_url: "https://accounts.google.com/samlrp/acs".into(),
                    google_entity_id: "google.com".into(),
                }),
            },
            google_sync: Default::default(),
            agent: Default::default(),
            marketplace: Default::default(),
            sso_partners: Vec::new(),
            webhooks: Vec::new(),
        }
    }

    #[test]
    fn validate_saml_config_disabled_idp() {
        let mut config = make_test_config();
        config.idp.enabled = false;
        let issues = validate_saml_config(&config);
        assert!(!issues.is_empty());
        assert!(issues[0].contains("not enabled"));
    }

    #[test]
    fn validate_saml_config_missing_public_url() {
        let mut config = make_test_config();
        config.chalk.public_url = None;
        let issues = validate_saml_config(&config);
        assert!(issues.iter().any(|i| i.contains("public_url")));
    }

    #[test]
    fn validate_saml_config_missing_cert_path() {
        let mut config = make_test_config();
        config.idp.saml_cert_path = None;
        let issues = validate_saml_config(&config);
        assert!(issues.iter().any(|i| i.contains("saml_cert_path")));
    }

    #[test]
    fn validate_saml_config_missing_key_path() {
        let mut config = make_test_config();
        config.idp.saml_key_path = None;
        let issues = validate_saml_config(&config);
        assert!(issues.iter().any(|i| i.contains("saml_key_path")));
    }

    #[test]
    fn validate_saml_config_missing_google_section() {
        let mut config = make_test_config();
        config.idp.google = None;
        let issues = validate_saml_config(&config);
        assert!(issues.iter().any(|i| i.contains("idp.google")));
    }

    #[test]
    fn validate_saml_config_empty_workspace_domain() {
        let mut config = make_test_config();
        config.idp.google.as_mut().unwrap().workspace_domain = String::new();
        let issues = validate_saml_config(&config);
        assert!(issues.iter().any(|i| i.contains("workspace_domain")));
    }

    #[test]
    fn validate_saml_config_empty_acs_url() {
        let mut config = make_test_config();
        config.idp.google.as_mut().unwrap().google_acs_url = String::new();
        let issues = validate_saml_config(&config);
        assert!(issues.iter().any(|i| i.contains("google_acs_url")));
    }

    #[test]
    fn validate_saml_config_empty_entity_id() {
        let mut config = make_test_config();
        config.idp.google.as_mut().unwrap().google_entity_id = String::new();
        let issues = validate_saml_config(&config);
        assert!(issues.iter().any(|i| i.contains("google_entity_id")));
    }

    #[test]
    fn validate_saml_config_cert_file_not_found() {
        let config = make_test_config();
        let issues = validate_saml_config(&config);
        // cert and key paths are /nonexistent/... so file-not-found warnings
        assert!(issues.iter().any(|i| i.contains("not found")));
    }
}
