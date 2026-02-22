//! TOML-based configuration system for Chalk.

use crate::error::{ChalkError, Result};
use crate::webhooks::models::{WebhookMode, WebhookSecurityMode};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level Chalk configuration, deserialized from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChalkConfig {
    pub chalk: ChalkSection,
    #[serde(default)]
    pub sis: SisConfig,
    #[serde(default)]
    pub idp: IdpConfig,
    #[serde(default)]
    pub google_sync: GoogleSyncConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub marketplace: MarketplaceConfig,
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
}

/// Core Chalk instance settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChalkSection {
    pub instance_name: String,
    pub data_dir: String,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub admin_password_hash: Option<String>,
}

/// Database backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "DatabaseDriver::default_driver")]
    pub driver: DatabaseDriver,
    /// SQLite file path (used when driver = "sqlite").
    #[serde(default)]
    pub path: Option<String>,
    /// PostgreSQL connection URL (used when driver = "postgres").
    #[serde(default)]
    pub url: Option<String>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            driver: DatabaseDriver::Sqlite,
            path: Some("/var/lib/chalk/chalk.db".into()),
            url: None,
        }
    }
}

/// Supported database drivers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseDriver {
    Sqlite,
    Postgres,
}

impl DatabaseDriver {
    fn default_driver() -> Self {
        Self::Sqlite
    }
}

/// SIS (Student Information System) integration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SisConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: SisProvider,
    #[serde(default)]
    pub base_url: String,
    /// OAuth 2.0 token endpoint URL. Required for Infinite Campus and Skyward
    /// (their token URL is not derivable from base_url). Optional for PowerSchool.
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default = "default_sync_schedule")]
    pub sync_schedule: String,
}

impl Default for SisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: SisProvider::PowerSchool,
            base_url: String::new(),
            token_url: None,
            client_id: String::new(),
            client_secret: String::new(),
            sync_schedule: default_sync_schedule(),
        }
    }
}

fn default_sync_schedule() -> String {
    "0 2 * * *".into()
}

/// Supported SIS providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SisProvider {
    #[default]
    #[serde(rename = "powerschool")]
    PowerSchool,
    #[serde(rename = "infinite_campus")]
    InfiniteCampus,
    #[serde(rename = "skyward")]
    Skyward,
}

/// Identity Provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub qr_badge_login: bool,
    #[serde(default)]
    pub picture_passwords: bool,
    #[serde(default)]
    pub saml_cert_path: Option<String>,
    #[serde(default)]
    pub saml_key_path: Option<String>,
    #[serde(default = "default_session_timeout")]
    pub session_timeout_minutes: u32,
    /// Pattern for generating default user passwords (e.g., `"{lastName}{birthYear}"`).
    #[serde(default)]
    pub default_password_pattern: Option<String>,
    /// Roles to auto-generate passwords for (e.g., `["student", "teacher"]`).
    #[serde(default)]
    pub default_password_roles: Vec<String>,
    #[serde(default)]
    pub google: Option<IdpGoogleConfig>,
}

impl Default for IdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            qr_badge_login: false,
            picture_passwords: false,
            saml_cert_path: None,
            saml_key_path: None,
            session_timeout_minutes: default_session_timeout(),
            default_password_pattern: None,
            default_password_roles: Vec::new(),
            google: None,
        }
    }
}

fn default_session_timeout() -> u32 {
    480
}

/// Google Workspace SAML integration settings for IDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpGoogleConfig {
    pub workspace_domain: String,
    pub google_acs_url: String,
    pub google_entity_id: String,
}

/// Google Workspace sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GoogleSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provision_users: bool,
    #[serde(default)]
    pub manage_ous: bool,
    #[serde(default)]
    pub suspend_inactive: bool,
    #[serde(default = "default_sync_schedule")]
    pub sync_schedule: String,
    #[serde(default)]
    pub service_account_key_path: Option<String>,
    #[serde(default)]
    pub admin_email: Option<String>,
    #[serde(default)]
    pub workspace_domain: Option<String>,
    #[serde(default)]
    pub ou_mapping: Option<OuMappingConfig>,
}

/// Organizational Unit path templates for Google Workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuMappingConfig {
    pub students: String,
    pub teachers: String,
    pub staff: String,
}

/// AI Agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Anonymous telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Marketplace integration configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MarketplaceConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Configuration for a webhook endpoint defined in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    pub secret: String,
    #[serde(default = "default_webhook_security")]
    pub security: WebhookSecurityMode,
    #[serde(default = "default_webhook_mode")]
    pub mode: WebhookMode,
    #[serde(default = "default_webhook_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub entity_types: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub excluded_fields: Vec<String>,
    #[serde(default)]
    pub org_sourced_ids: Vec<String>,
}

fn default_webhook_security() -> WebhookSecurityMode {
    WebhookSecurityMode::SignOnly
}

fn default_webhook_mode() -> WebhookMode {
    WebhookMode::Batched
}

fn default_webhook_enabled() -> bool {
    true
}

impl ChalkConfig {
    /// Load configuration from a TOML file at the given path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| ChalkError::Config(format!("failed to parse config: {e}")))?;
        Ok(config)
    }

    /// Validate the configuration, returning an error for invalid combinations.
    pub fn validate(&self) -> Result<()> {
        if self.chalk.instance_name.is_empty() {
            return Err(ChalkError::Config(
                "chalk.instance_name must not be empty".into(),
            ));
        }

        if self.chalk.data_dir.is_empty() {
            return Err(ChalkError::Config(
                "chalk.data_dir must not be empty".into(),
            ));
        }

        // Database validation
        match self.chalk.database.driver {
            DatabaseDriver::Sqlite => {
                if self.chalk.database.path.is_none() {
                    return Err(ChalkError::Config(
                        "chalk.database.path is required when driver is sqlite".into(),
                    ));
                }
            }
            DatabaseDriver::Postgres => {
                if self.chalk.database.url.is_none() {
                    return Err(ChalkError::Config(
                        "chalk.database.url is required when driver is postgres".into(),
                    ));
                }
            }
        }

        // SIS validation
        if self.sis.enabled && self.sis.base_url.is_empty() {
            return Err(ChalkError::Config(
                "sis.base_url is required when SIS is enabled".into(),
            ));
        }

        // token_url is required for IC and Skyward (not derivable from base_url)
        if self.sis.enabled
            && matches!(
                self.sis.provider,
                SisProvider::InfiniteCampus | SisProvider::Skyward
            )
            && self.sis.token_url.is_none()
        {
            return Err(ChalkError::Config(format!(
                "sis.token_url is required for {:?} provider",
                self.sis.provider
            )));
        }

        // IDP validation
        if self.idp.enabled {
            if self.idp.saml_cert_path.is_none() {
                return Err(ChalkError::Config(
                    "idp.saml_cert_path is required when IDP is enabled".into(),
                ));
            }
            if self.idp.saml_key_path.is_none() {
                return Err(ChalkError::Config(
                    "idp.saml_key_path is required when IDP is enabled".into(),
                ));
            }
            if self.chalk.public_url.is_none() {
                return Err(ChalkError::Config(
                    "chalk.public_url is required when IDP is enabled".into(),
                ));
            }
        }

        // Google Sync validation
        if self.google_sync.enabled {
            if self.google_sync.service_account_key_path.is_none() {
                return Err(ChalkError::Config(
                    "google_sync.service_account_key_path is required when Google Sync is enabled"
                        .into(),
                ));
            }
            if self.google_sync.admin_email.is_none() {
                return Err(ChalkError::Config(
                    "google_sync.admin_email is required when Google Sync is enabled".into(),
                ));
            }
            if self.google_sync.workspace_domain.is_none() {
                return Err(ChalkError::Config(
                    "google_sync.workspace_domain is required when Google Sync is enabled".into(),
                ));
            }
            if let Some(ref key_path) = self.google_sync.service_account_key_path {
                if !Path::new(key_path).exists() {
                    return Err(ChalkError::Config(format!(
                        "google_sync.service_account_key_path file does not exist: {key_path}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Generate a sensible default configuration.
    pub fn generate_default() -> Self {
        Self {
            chalk: ChalkSection {
                instance_name: "My School District".into(),
                data_dir: "/var/lib/chalk".into(),
                public_url: None,
                database: DatabaseConfig::default(),
                telemetry: TelemetryConfig::default(),
                admin_password_hash: None,
            },
            sis: SisConfig::default(),
            idp: IdpConfig::default(),
            google_sync: GoogleSyncConfig::default(),
            agent: AgentConfig::default(),
            marketplace: MarketplaceConfig::default(),
            webhooks: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SAMPLE_TOML: &str = r#"
[chalk]
instance_name = "Springfield USD"
data_dir = "/var/lib/chalk"
public_url = "https://chalk.springfield.k12.us"

[chalk.database]
driver = "sqlite"
path = "/var/lib/chalk/chalk.db"

[chalk.telemetry]
enabled = false

[sis]
enabled = true
provider = "powerschool"
base_url = "https://powerschool.springfield.k12.us"
client_id = "abc"
client_secret = "secret"
sync_schedule = "0 2 * * *"

[idp]
enabled = true
qr_badge_login = true
picture_passwords = true
saml_cert_path = "/var/lib/chalk/saml.crt"
saml_key_path = "/var/lib/chalk/saml.key"
session_timeout_minutes = 480

[idp.google]
workspace_domain = "springfield.k12.us"
google_acs_url = "https://accounts.google.com/samlrp/acs"
google_entity_id = "google.com"

[google_sync]
enabled = true
provision_users = true
manage_ous = true
suspend_inactive = true
sync_schedule = "0 3 * * *"
service_account_key_path = "/var/lib/chalk/google-sa.json"
admin_email = "admin@springfield.k12.us"
workspace_domain = "springfield.k12.us"

[google_sync.ou_mapping]
students = "/Students/{school}/{grade}"
teachers = "/Teachers/{school}"
staff = "/Staff/{school}"

[agent]
enabled = false

[marketplace]
enabled = false
"#;

    fn parse_sample() -> ChalkConfig {
        toml::from_str(SAMPLE_TOML).expect("sample TOML should parse")
    }

    #[test]
    fn parse_full_config() {
        let cfg = parse_sample();
        assert_eq!(cfg.chalk.instance_name, "Springfield USD");
        assert_eq!(cfg.chalk.data_dir, "/var/lib/chalk");
        assert_eq!(
            cfg.chalk.public_url.as_deref(),
            Some("https://chalk.springfield.k12.us")
        );
        assert_eq!(cfg.chalk.database.driver, DatabaseDriver::Sqlite);
        assert_eq!(
            cfg.chalk.database.path.as_deref(),
            Some("/var/lib/chalk/chalk.db")
        );
        assert!(cfg.sis.enabled);
        assert_eq!(cfg.sis.provider, SisProvider::PowerSchool);
        assert!(cfg.idp.enabled);
        assert!(cfg.idp.qr_badge_login);
        assert!(cfg.idp.picture_passwords);
        assert_eq!(
            cfg.idp.saml_cert_path.as_deref(),
            Some("/var/lib/chalk/saml.crt")
        );
        assert_eq!(
            cfg.idp.saml_key_path.as_deref(),
            Some("/var/lib/chalk/saml.key")
        );
        assert_eq!(cfg.idp.session_timeout_minutes, 480);
        let google = cfg.idp.google.as_ref().unwrap();
        assert_eq!(google.workspace_domain, "springfield.k12.us");
        assert!(cfg.google_sync.enabled);
        assert!(cfg.google_sync.provision_users);
        assert!(cfg.google_sync.manage_ous);
        assert!(cfg.google_sync.suspend_inactive);
        assert_eq!(
            cfg.google_sync.service_account_key_path.as_deref(),
            Some("/var/lib/chalk/google-sa.json")
        );
        assert_eq!(
            cfg.google_sync.admin_email.as_deref(),
            Some("admin@springfield.k12.us")
        );
        assert_eq!(
            cfg.google_sync.workspace_domain.as_deref(),
            Some("springfield.k12.us")
        );
        let ou = cfg.google_sync.ou_mapping.as_ref().unwrap();
        assert_eq!(ou.students, "/Students/{school}/{grade}");
        assert!(!cfg.agent.enabled);
        assert!(!cfg.marketplace.enabled);
        assert!(!cfg.chalk.telemetry.enabled);
    }

    #[test]
    fn roundtrip_serialization() {
        let cfg = parse_sample();
        let serialized = toml::to_string(&cfg).expect("should serialize");
        let deserialized: ChalkConfig =
            toml::from_str(&serialized).expect("should deserialize roundtrip");
        assert_eq!(deserialized.chalk.instance_name, cfg.chalk.instance_name);
        assert_eq!(deserialized.sis.provider, cfg.sis.provider);
        assert_eq!(
            deserialized.chalk.database.driver,
            cfg.chalk.database.driver
        );
    }

    #[test]
    fn generate_default_is_valid() {
        let cfg = ChalkConfig::generate_default();
        cfg.validate().expect("default config should be valid");
    }

    #[test]
    fn validate_requires_instance_name() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.instance_name = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("instance_name"));
    }

    #[test]
    fn validate_requires_data_dir() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.data_dir = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("data_dir"));
    }

    #[test]
    fn validate_requires_sqlite_path() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.database.driver = DatabaseDriver::Sqlite;
        cfg.chalk.database.path = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("path"));
    }

    #[test]
    fn validate_requires_postgres_url() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.database.driver = DatabaseDriver::Postgres;
        cfg.chalk.database.url = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("url"));
    }

    #[test]
    fn validate_postgres_with_url_passes() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.database.driver = DatabaseDriver::Postgres;
        cfg.chalk.database.path = None;
        cfg.chalk.database.url = Some("postgres://localhost/chalk".into());
        cfg.validate().expect("postgres with url should be valid");
    }

    #[test]
    fn validate_sis_requires_base_url_when_enabled() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.base_url = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_sis_disabled_no_base_url_ok() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = false;
        cfg.sis.base_url = String::new();
        cfg.validate()
            .expect("disabled SIS should not require base_url");
    }

    #[test]
    fn validate_ic_requires_token_url() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.provider = SisProvider::InfiniteCampus;
        cfg.sis.base_url = "https://ic.example.com".into();
        cfg.sis.token_url = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("token_url"));
    }

    #[test]
    fn validate_skyward_requires_token_url() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.provider = SisProvider::Skyward;
        cfg.sis.base_url = "https://skyward.example.com".into();
        cfg.sis.token_url = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("token_url"));
    }

    #[test]
    fn validate_ic_with_token_url_passes() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.provider = SisProvider::InfiniteCampus;
        cfg.sis.base_url = "https://ic.example.com".into();
        cfg.sis.token_url = Some("https://ic.example.com/oauth/token".into());
        cfg.validate().expect("IC with token_url should be valid");
    }

    #[test]
    fn validate_powerschool_no_token_url_ok() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.provider = SisProvider::PowerSchool;
        cfg.sis.base_url = "https://ps.example.com".into();
        cfg.sis.token_url = None;
        cfg.validate()
            .expect("PowerSchool should not require token_url");
    }

    #[test]
    fn token_url_roundtrip_serialization() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.token_url = Some("https://example.com/oauth/token".into());
        let serialized = toml::to_string(&cfg).expect("should serialize");
        let deserialized: ChalkConfig =
            toml::from_str(&serialized).expect("should deserialize roundtrip");
        assert_eq!(
            deserialized.sis.token_url.as_deref(),
            Some("https://example.com/oauth/token")
        );
    }

    #[test]
    fn sis_provider_serialization() {
        assert_eq!(
            serde_json::to_string(&SisProvider::PowerSchool).unwrap(),
            "\"powerschool\""
        );
        assert_eq!(
            serde_json::to_string(&SisProvider::InfiniteCampus).unwrap(),
            "\"infinite_campus\""
        );
        assert_eq!(
            serde_json::to_string(&SisProvider::Skyward).unwrap(),
            "\"skyward\""
        );
    }

    #[test]
    fn database_driver_serialization() {
        assert_eq!(
            serde_json::to_string(&DatabaseDriver::Sqlite).unwrap(),
            "\"sqlite\""
        );
        assert_eq!(
            serde_json::to_string(&DatabaseDriver::Postgres).unwrap(),
            "\"postgres\""
        );
    }

    #[test]
    fn load_from_file() {
        let dir = std::env::temp_dir().join("chalk_test_config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chalk.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(SAMPLE_TOML.as_bytes()).unwrap();

        let cfg = ChalkConfig::load(&path).expect("should load from file");
        assert_eq!(cfg.chalk.instance_name, "Springfield USD");

        // cleanup
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn load_nonexistent_file_returns_io_error() {
        let result = ChalkConfig::load(Path::new("/nonexistent/chalk.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn load_invalid_toml_returns_config_error() {
        let dir = std::env::temp_dir().join("chalk_test_bad_toml");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "this is [[[not valid toml").unwrap();

        let result = ChalkConfig::load(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("config"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn minimal_config_parses() {
        let minimal = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp/chalk"
"#;
        let cfg: ChalkConfig = toml::from_str(minimal).expect("minimal config should parse");
        assert_eq!(cfg.chalk.instance_name, "Test");
        assert!(!cfg.sis.enabled);
        assert!(!cfg.idp.enabled);
    }

    #[test]
    fn all_sis_providers_deserialize() {
        for (s, expected) in [
            ("\"powerschool\"", SisProvider::PowerSchool),
            ("\"infinite_campus\"", SisProvider::InfiniteCampus),
            ("\"skyward\"", SisProvider::Skyward),
        ] {
            let parsed: SisProvider = serde_json::from_str(s).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn both_db_drivers_deserialize() {
        for (s, expected) in [
            ("\"sqlite\"", DatabaseDriver::Sqlite),
            ("\"postgres\"", DatabaseDriver::Postgres),
        ] {
            let parsed: DatabaseDriver = serde_json::from_str(s).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn validate_idp_requires_cert_path() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = true;
        cfg.idp.saml_cert_path = None;
        cfg.idp.saml_key_path = Some("/tmp/key.pem".into());
        cfg.chalk.public_url = Some("https://chalk.example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("saml_cert_path"));
    }

    #[test]
    fn validate_idp_requires_key_path() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = true;
        cfg.idp.saml_cert_path = Some("/tmp/cert.pem".into());
        cfg.idp.saml_key_path = None;
        cfg.chalk.public_url = Some("https://chalk.example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("saml_key_path"));
    }

    #[test]
    fn validate_idp_requires_public_url() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = true;
        cfg.idp.saml_cert_path = Some("/tmp/cert.pem".into());
        cfg.idp.saml_key_path = Some("/tmp/key.pem".into());
        cfg.chalk.public_url = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("public_url"));
    }

    #[test]
    fn validate_idp_fully_configured_passes() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = true;
        cfg.idp.saml_cert_path = Some("/tmp/cert.pem".into());
        cfg.idp.saml_key_path = Some("/tmp/key.pem".into());
        cfg.chalk.public_url = Some("https://chalk.example.com".into());
        cfg.validate().expect("fully configured IDP should pass");
    }

    #[test]
    fn validate_idp_disabled_no_validation() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = false;
        cfg.idp.saml_cert_path = None;
        cfg.idp.saml_key_path = None;
        cfg.validate()
            .expect("disabled IDP should not require cert/key");
    }

    #[test]
    fn validate_google_sync_requires_service_account_key() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path = None;
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = Some("example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("service_account_key_path"));
    }

    #[test]
    fn validate_google_sync_requires_admin_email() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path = Some("/tmp/sa.json".into());
        cfg.google_sync.admin_email = None;
        cfg.google_sync.workspace_domain = Some("example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("admin_email"));
    }

    #[test]
    fn validate_google_sync_requires_workspace_domain() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path = Some("/tmp/sa.json".into());
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("workspace_domain"));
    }

    #[test]
    fn validate_google_sync_fully_configured_passes() {
        let dir = std::env::temp_dir().join("chalk_test_gsync_valid");
        std::fs::create_dir_all(&dir).unwrap();
        let sa_path = dir.join("sa.json");
        std::fs::write(&sa_path, "{}").unwrap();

        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path =
            Some(sa_path.to_str().unwrap().to_string());
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = Some("example.com".into());
        cfg.validate()
            .expect("fully configured Google Sync should pass");

        std::fs::remove_file(&sa_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn validate_google_sync_key_file_must_exist() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path =
            Some("/nonexistent/path/sa-key.json".into());
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = Some("example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn validate_google_sync_disabled_no_validation() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = false;
        cfg.google_sync.service_account_key_path = None;
        cfg.validate()
            .expect("disabled Google Sync should not require keys");
    }

    #[test]
    fn idp_session_timeout_default() {
        let cfg = ChalkConfig::generate_default();
        assert_eq!(cfg.idp.session_timeout_minutes, 480);
    }

    #[test]
    fn idp_password_pattern_defaults() {
        let cfg = ChalkConfig::generate_default();
        assert!(cfg.idp.default_password_pattern.is_none());
        assert!(cfg.idp.default_password_roles.is_empty());
    }

    #[test]
    fn idp_password_pattern_parses() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[idp]
default_password_pattern = "{lastName}{birthYear}"
default_password_roles = ["student", "teacher"]
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            cfg.idp.default_password_pattern.as_deref(),
            Some("{lastName}{birthYear}")
        );
        assert_eq!(cfg.idp.default_password_roles, vec!["student", "teacher"]);
    }

    #[test]
    fn webhook_config_parses_from_toml() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[[webhooks]]
name = "My LMS"
url = "https://lms.example.com/webhook"
secret = "super-secret"
security = "sign_only"
mode = "batched"
enabled = true
entity_types = ["user", "enrollment"]
roles = ["student"]
excluded_fields = ["demographics.birthDate"]
org_sourced_ids = ["org-1"]

[[webhooks]]
name = "Analytics"
url = "https://analytics.example.com/hook"
secret = "analytics-key"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.webhooks.len(), 2);

        let first = &cfg.webhooks[0];
        assert_eq!(first.name, "My LMS");
        assert_eq!(first.url, "https://lms.example.com/webhook");
        assert_eq!(first.secret, "super-secret");
        assert_eq!(
            first.security,
            crate::webhooks::models::WebhookSecurityMode::SignOnly
        );
        assert_eq!(first.mode, crate::webhooks::models::WebhookMode::Batched);
        assert!(first.enabled);
        assert_eq!(first.entity_types, vec!["user", "enrollment"]);
        assert_eq!(first.roles, vec!["student"]);
        assert_eq!(first.excluded_fields, vec!["demographics.birthDate"]);
        assert_eq!(first.org_sourced_ids, vec!["org-1"]);

        let second = &cfg.webhooks[1];
        assert_eq!(second.name, "Analytics");
        assert!(second.enabled); // default
        assert_eq!(
            second.security,
            crate::webhooks::models::WebhookSecurityMode::SignOnly
        ); // default
        assert_eq!(
            second.mode,
            crate::webhooks::models::WebhookMode::Batched
        ); // default
        assert!(second.entity_types.is_empty());
    }

    #[test]
    fn webhook_config_defaults_when_absent() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.webhooks.is_empty());
    }

    #[test]
    fn webhook_config_encrypted_mode() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[[webhooks]]
name = "Encrypted Hook"
url = "https://example.com/hook"
secret = "key"
security = "encrypted"
mode = "per_entity"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.webhooks.len(), 1);
        assert_eq!(
            cfg.webhooks[0].security,
            crate::webhooks::models::WebhookSecurityMode::Encrypted
        );
        assert_eq!(
            cfg.webhooks[0].mode,
            crate::webhooks::models::WebhookMode::PerEntity
        );
    }

    #[test]
    fn webhook_config_roundtrip_serialization() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[[webhooks]]
name = "Hook"
url = "https://example.com/hook"
secret = "key"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        let serialized = toml::to_string(&cfg).expect("should serialize");
        let deserialized: ChalkConfig =
            toml::from_str(&serialized).expect("should deserialize roundtrip");
        assert_eq!(deserialized.webhooks.len(), 1);
        assert_eq!(deserialized.webhooks[0].name, "Hook");
        assert_eq!(deserialized.webhooks[0].url, "https://example.com/hook");
    }

    #[test]
    fn ou_mapping_roundtrip() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.ou_mapping = Some(OuMappingConfig {
            students: "/Students/{school}/{grade}".into(),
            teachers: "/Teachers/{school}".into(),
            staff: "/Staff".into(),
        });
        let serialized = toml::to_string(&cfg).expect("should serialize");
        let deserialized: ChalkConfig =
            toml::from_str(&serialized).expect("should deserialize roundtrip");
        let ou = deserialized.google_sync.ou_mapping.unwrap();
        assert_eq!(ou.students, "/Students/{school}/{grade}");
        assert_eq!(ou.teachers, "/Teachers/{school}");
        assert_eq!(ou.staff, "/Staff");
    }
}
