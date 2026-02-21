use std::path::Path;

use chalk_core::config::{
    ChalkConfig, ChalkSection, DatabaseConfig, DatabaseDriver, IdpConfig, SisConfig, SisProvider,
};
use chalk_core::crypto;
use chalk_core::db::DatabasePool;
use chalk_idp::certs::generate_saml_keypair;
use tracing::info;

/// Run the `init` command: create data directory, write default config, and set up the database.
pub async fn run(data_dir: &str, provider: &str) -> anyhow::Result<()> {
    let data_path = Path::new(data_dir);

    // Create data directory if it doesn't exist
    if !data_path.exists() {
        std::fs::create_dir_all(data_path)?;
        info!("Created data directory: {}", data_dir);
    }

    let sis_provider = match provider {
        "powerschool" => SisProvider::PowerSchool,
        "infinite_campus" => SisProvider::InfiniteCampus,
        "skyward" => SisProvider::Skyward,
        other => {
            anyhow::bail!(
                "Unknown SIS provider: {other}. Supported: powerschool, infinite_campus, skyward"
            );
        }
    };

    let db_path = data_path.join("chalk.db");
    let db_path_str = db_path.to_string_lossy().to_string();

    // IC and Skyward need a token_url placeholder since it's not derivable from base_url
    let token_url = match sis_provider {
        SisProvider::InfiniteCampus | SisProvider::Skyward => {
            Some("https://your-sis-instance.example.com/oauth/token".into())
        }
        SisProvider::PowerSchool => None,
    };

    // Generate admin password hash (default password: "chalk-admin")
    let default_password = "chalk-admin";
    let admin_password_hash = chalk_console::auth::hash_password(default_password)
        .map_err(|e| anyhow::anyhow!("failed to hash admin password: {e}"))?;

    // Generate master encryption key
    let master_key = crypto::generate_key();
    let master_key_path = data_path.join("chalk.key");
    std::fs::write(&master_key_path, master_key)?;
    info!(
        "Generated master encryption key: {}",
        master_key_path.display()
    );

    let config = ChalkConfig {
        chalk: ChalkSection {
            instance_name: "My School District".into(),
            data_dir: data_dir.to_string(),
            public_url: None,
            database: DatabaseConfig {
                driver: DatabaseDriver::Sqlite,
                path: Some(db_path_str.clone()),
                url: None,
            },
            telemetry: Default::default(),
            admin_password_hash: Some(admin_password_hash),
        },
        sis: SisConfig {
            provider: sis_provider,
            token_url,
            ..Default::default()
        },
        idp: IdpConfig {
            saml_cert_path: Some(
                data_path
                    .join("saml_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            ),
            saml_key_path: Some(data_path.join("saml_key.pem").to_string_lossy().to_string()),
            ..Default::default()
        },
        google_sync: Default::default(),
        agent: Default::default(),
        marketplace: Default::default(),
    };

    // Generate SAML keypair for IDP
    let (cert_pem, key_pem) = generate_saml_keypair("Chalk IDP")?;
    let cert_path = data_path.join("saml_cert.pem");
    let saml_key_path = data_path.join("saml_key.pem");
    std::fs::write(&cert_path, &cert_pem)?;
    std::fs::write(&saml_key_path, &key_pem)?;
    info!(
        "Generated SAML keypair: {}, {}",
        cert_path.display(),
        saml_key_path.display()
    );

    // Write config file
    let config_path = data_path.join("chalk.toml");
    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, &toml_str)?;
    info!("Wrote configuration to {}", config_path.display());

    // Create database and run migrations
    let connect_str = format!("sqlite:{}?mode=rwc", db_path_str);
    DatabasePool::new_sqlite(&connect_str).await?;
    info!("Database initialized at {}", db_path_str);

    println!("Chalk initialized successfully!");
    println!("  Data directory: {}", data_dir);
    println!("  Configuration: {}", config_path.display());
    println!("  Database:      {}", db_path_str);
    println!("  SAML cert:     {}", cert_path.display());
    println!("  SAML key:      {}", saml_key_path.display());
    println!("  Master key:    {}", master_key_path.display());
    println!("  Admin password: {}", default_password);
    println!();
    println!("Next steps:");
    println!(
        "  1. Edit {} to configure your SIS connection",
        config_path.display()
    );
    println!("  2. Change the default admin password");
    println!("  3. Run `chalk sync --dry-run` to test your connection");
    println!("  4. Run `chalk sync` to perform the first sync");
    println!("  5. Enable IDP in config and configure SAML for Google Workspace");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init_creates_files_in_temp_dir() {
        let temp_dir = std::env::temp_dir().join("chalk_test_init");
        // Clean up from any previous run
        let _ = std::fs::remove_dir_all(&temp_dir);

        let data_dir = temp_dir.to_string_lossy().to_string();
        run(&data_dir, "powerschool").await.unwrap();

        // Verify data directory was created
        assert!(temp_dir.exists());

        // Verify config file was created and is valid TOML
        let config_path = temp_dir.join("chalk.toml");
        assert!(config_path.exists());
        let content = std::fs::read_to_string(&config_path).unwrap();
        let config: ChalkConfig = toml::from_str(&content).unwrap();
        assert_eq!(config.chalk.instance_name, "My School District");
        assert_eq!(config.chalk.data_dir, data_dir);
        assert_eq!(config.sis.provider, SisProvider::PowerSchool);

        // Verify database file was created
        let db_path = temp_dir.join("chalk.db");
        assert!(db_path.exists());

        // Verify SAML cert and key were generated
        let saml_cert_path = temp_dir.join("saml_cert.pem");
        let saml_key_path = temp_dir.join("saml_key.pem");
        assert!(saml_cert_path.exists());
        assert!(saml_key_path.exists());

        let cert_content = std::fs::read_to_string(&saml_cert_path).unwrap();
        assert!(cert_content.starts_with("-----BEGIN CERTIFICATE-----"));

        let key_content = std::fs::read_to_string(&saml_key_path).unwrap();
        assert!(key_content.starts_with("-----BEGIN PRIVATE KEY-----"));

        // Verify config references the cert paths
        assert_eq!(
            config.idp.saml_cert_path.as_deref(),
            Some(saml_cert_path.to_string_lossy().as_ref())
        );
        assert_eq!(
            config.idp.saml_key_path.as_deref(),
            Some(saml_key_path.to_string_lossy().as_ref())
        );

        // Verify master key was generated
        let master_key_path = temp_dir.join("chalk.key");
        assert!(master_key_path.exists());
        let key_bytes = std::fs::read(&master_key_path).unwrap();
        assert_eq!(key_bytes.len(), 32);

        // Verify admin password hash is set in config
        assert!(config.chalk.admin_password_hash.is_some());

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn init_rejects_unknown_provider() {
        let temp_dir = std::env::temp_dir().join("chalk_test_init_bad_provider");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let data_dir = temp_dir.to_string_lossy().to_string();
        let result = run(&data_dir, "unknown_provider").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown SIS provider"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn init_accepts_all_valid_providers() {
        for provider in &["powerschool", "infinite_campus", "skyward"] {
            let temp_dir = std::env::temp_dir().join(format!("chalk_test_init_{}", provider));
            let _ = std::fs::remove_dir_all(&temp_dir);

            let data_dir = temp_dir.to_string_lossy().to_string();
            run(&data_dir, provider).await.unwrap();

            let config_path = temp_dir.join("chalk.toml");
            let content = std::fs::read_to_string(&config_path).unwrap();
            let config: ChalkConfig = toml::from_str(&content).unwrap();

            let expected_provider = match *provider {
                "powerschool" => SisProvider::PowerSchool,
                "infinite_campus" => SisProvider::InfiniteCampus,
                "skyward" => SisProvider::Skyward,
                _ => unreachable!(),
            };
            assert_eq!(config.sis.provider, expected_provider);

            let _ = std::fs::remove_dir_all(&temp_dir);
        }
    }
}
