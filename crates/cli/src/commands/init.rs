use std::path::Path;

use chalk_core::config::{
    ChalkConfig, ChalkSection, DatabaseConfig, DatabaseDriver, SisConfig, SisProvider,
};
use chalk_core::db::DatabasePool;
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
        },
        sis: SisConfig {
            provider: sis_provider,
            token_url,
            ..Default::default()
        },
        idp: Default::default(),
        google_sync: Default::default(),
        agent: Default::default(),
        marketplace: Default::default(),
    };

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
    println!();
    println!("Next steps:");
    println!(
        "  1. Edit {} to configure your SIS connection",
        config_path.display()
    );
    println!("  2. Run `chalk sync --dry-run` to test your connection");
    println!("  3. Run `chalk sync` to perform the first sync");

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
