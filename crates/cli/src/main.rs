use clap::Parser;
use tracing_subscriber::EnvFilter;

mod commands;

#[derive(Parser)]
#[command(name = "chalk", about = "K-12 SIS integration platform", version)]
struct Cli {
    /// Path to configuration file
    #[arg(long, default_value = "chalk.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Initialize Chalk data directory and configuration
    Init {
        /// Data directory path
        #[arg(long, default_value = "/var/lib/chalk")]
        data_dir: String,
        /// SIS provider
        #[arg(long, default_value = "powerschool")]
        provider: String,
    },
    /// Run a sync from the configured SIS
    Sync {
        /// Preview changes without applying
        #[arg(long)]
        dry_run: bool,
    },
    /// Show sync status and statistics
    Status,
    /// Check for updates and optionally self-update
    Update {
        /// Only check for a new version without installing
        #[arg(long)]
        check: bool,
    },
    /// Start the admin console web server
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,
    },
    /// Sync roster data to Google Workspace
    GoogleSync {
        /// Preview changes without applying
        #[arg(long)]
        dry_run: bool,
    },
    /// Import OneRoster CSV files into the database
    Import {
        /// Path to directory containing OneRoster CSV files
        #[arg(long)]
        dir: String,
        /// Preview parsed data without writing to the database
        #[arg(long)]
        dry_run: bool,
    },
    /// Export database contents as OneRoster CSV files
    Export {
        /// Output directory for CSV files
        #[arg(long)]
        dir: String,
    },
    /// Generate default passwords for users
    Passwords {
        #[command(subcommand)]
        action: PasswordsAction,
    },
    /// Migrate from Clever or ClassLink
    Migrate {
        /// Source platform: clever or classlink
        #[arg(long)]
        from: String,
        /// Path to the export directory
        #[arg(long)]
        path: String,
        /// Preview parsed data without writing to the database
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(clap::Subcommand)]
enum PasswordsAction {
    /// Generate default passwords from the configured pattern
    Generate {
        /// Generate for a specific user by sourced_id
        #[arg(long)]
        user: Option<String>,
        /// Regenerate even if a password already exists
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { data_dir, provider } => {
            commands::init::run(&data_dir, &provider).await?;
        }
        Commands::Sync { dry_run } => {
            commands::sync::run(&cli.config, dry_run).await?;
        }
        Commands::Status => {
            commands::status::run(&cli.config).await?;
        }
        Commands::Update { check } => {
            commands::update::run(check).await?;
        }
        Commands::Serve { port } => {
            commands::serve::run(&cli.config, port).await?;
        }
        Commands::GoogleSync { dry_run } => {
            commands::google_sync::run(&cli.config, dry_run).await?;
        }
        Commands::Import { dir, dry_run } => {
            commands::import::run(&cli.config, &dir, dry_run).await?;
        }
        Commands::Export { dir } => {
            commands::export::run(&cli.config, &dir).await?;
        }
        Commands::Passwords { action } => match action {
            PasswordsAction::Generate { user, force } => {
                commands::passwords::run(&cli.config, user.as_deref(), force).await?;
            }
        },
        Commands::Migrate {
            from,
            path,
            dry_run,
        } => {
            commands::migrate::run(&cli.config, &from, &path, dry_run).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn cli_parse_init_defaults() {
        let cli = Cli::parse_from(["chalk", "init"]);
        assert_eq!(cli.config, "chalk.toml");
        match cli.command {
            Commands::Init { data_dir, provider } => {
                assert_eq!(data_dir, "/var/lib/chalk");
                assert_eq!(provider, "powerschool");
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_init_custom() {
        let cli = Cli::parse_from([
            "chalk",
            "--config",
            "/etc/chalk.toml",
            "init",
            "--data-dir",
            "/opt/chalk",
            "--provider",
            "skyward",
        ]);
        assert_eq!(cli.config, "/etc/chalk.toml");
        match cli.command {
            Commands::Init { data_dir, provider } => {
                assert_eq!(data_dir, "/opt/chalk");
                assert_eq!(provider, "skyward");
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn cli_parse_sync_defaults() {
        let cli = Cli::parse_from(["chalk", "sync"]);
        match cli.command {
            Commands::Sync { dry_run } => {
                assert!(!dry_run);
            }
            _ => panic!("expected Sync command"),
        }
    }

    #[test]
    fn cli_parse_sync_dry_run() {
        let cli = Cli::parse_from(["chalk", "sync", "--dry-run"]);
        match cli.command {
            Commands::Sync { dry_run } => {
                assert!(dry_run);
            }
            _ => panic!("expected Sync command"),
        }
    }

    #[test]
    fn cli_parse_status() {
        let cli = Cli::parse_from(["chalk", "status"]);
        assert!(matches!(cli.command, Commands::Status));
    }

    #[test]
    fn cli_parse_update() {
        let cli = Cli::parse_from(["chalk", "update"]);
        match cli.command {
            Commands::Update { check } => {
                assert!(!check);
            }
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn cli_parse_update_check() {
        let cli = Cli::parse_from(["chalk", "update", "--check"]);
        match cli.command {
            Commands::Update { check } => {
                assert!(check);
            }
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn cli_parse_serve_defaults() {
        let cli = Cli::parse_from(["chalk", "serve"]);
        match cli.command {
            Commands::Serve { port } => {
                assert_eq!(port, 8080);
            }
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn cli_parse_serve_custom_port() {
        let cli = Cli::parse_from(["chalk", "serve", "--port", "3000"]);
        match cli.command {
            Commands::Serve { port } => {
                assert_eq!(port, 3000);
            }
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn cli_parse_google_sync_defaults() {
        let cli = Cli::parse_from(["chalk", "google-sync"]);
        match cli.command {
            Commands::GoogleSync { dry_run } => {
                assert!(!dry_run);
            }
            _ => panic!("expected GoogleSync command"),
        }
    }

    #[test]
    fn cli_parse_google_sync_dry_run() {
        let cli = Cli::parse_from(["chalk", "google-sync", "--dry-run"]);
        match cli.command {
            Commands::GoogleSync { dry_run } => {
                assert!(dry_run);
            }
            _ => panic!("expected GoogleSync command"),
        }
    }

    #[test]
    fn cli_parse_import() {
        let cli = Cli::parse_from(["chalk", "import", "--dir", "/tmp/oneroster"]);
        match cli.command {
            Commands::Import { dir, dry_run } => {
                assert_eq!(dir, "/tmp/oneroster");
                assert!(!dry_run);
            }
            _ => panic!("expected Import command"),
        }
    }

    #[test]
    fn cli_parse_import_dry_run() {
        let cli = Cli::parse_from(["chalk", "import", "--dir", "/tmp/oneroster", "--dry-run"]);
        match cli.command {
            Commands::Import { dir, dry_run } => {
                assert_eq!(dir, "/tmp/oneroster");
                assert!(dry_run);
            }
            _ => panic!("expected Import command"),
        }
    }

    #[test]
    fn cli_parse_export() {
        let cli = Cli::parse_from(["chalk", "export", "--dir", "/tmp/output"]);
        match cli.command {
            Commands::Export { dir } => {
                assert_eq!(dir, "/tmp/output");
            }
            _ => panic!("expected Export command"),
        }
    }

    #[test]
    fn cli_parse_migrate_clever() {
        let cli = Cli::parse_from([
            "chalk",
            "migrate",
            "--from",
            "clever",
            "--path",
            "/tmp/clever-export",
        ]);
        match cli.command {
            Commands::Migrate {
                from,
                path,
                dry_run,
            } => {
                assert_eq!(from, "clever");
                assert_eq!(path, "/tmp/clever-export");
                assert!(!dry_run);
            }
            _ => panic!("expected Migrate command"),
        }
    }

    #[test]
    fn cli_parse_migrate_classlink() {
        let cli = Cli::parse_from([
            "chalk",
            "migrate",
            "--from",
            "classlink",
            "--path",
            "/tmp/classlink-export",
        ]);
        match cli.command {
            Commands::Migrate {
                from,
                path,
                dry_run,
            } => {
                assert_eq!(from, "classlink");
                assert_eq!(path, "/tmp/classlink-export");
                assert!(!dry_run);
            }
            _ => panic!("expected Migrate command"),
        }
    }

    #[test]
    fn cli_parse_passwords_generate_defaults() {
        let cli = Cli::parse_from(["chalk", "passwords", "generate"]);
        match cli.command {
            Commands::Passwords { action } => match action {
                PasswordsAction::Generate { user, force } => {
                    assert!(user.is_none());
                    assert!(!force);
                }
            },
            _ => panic!("expected Passwords command"),
        }
    }

    #[test]
    fn cli_parse_passwords_generate_user() {
        let cli = Cli::parse_from(["chalk", "passwords", "generate", "--user", "user-001"]);
        match cli.command {
            Commands::Passwords { action } => match action {
                PasswordsAction::Generate { user, force } => {
                    assert_eq!(user.as_deref(), Some("user-001"));
                    assert!(!force);
                }
            },
            _ => panic!("expected Passwords command"),
        }
    }

    #[test]
    fn cli_parse_passwords_generate_force() {
        let cli = Cli::parse_from(["chalk", "passwords", "generate", "--force"]);
        match cli.command {
            Commands::Passwords { action } => match action {
                PasswordsAction::Generate { user, force } => {
                    assert!(user.is_none());
                    assert!(force);
                }
            },
            _ => panic!("expected Passwords command"),
        }
    }

    #[test]
    fn cli_parse_passwords_generate_user_and_force() {
        let cli = Cli::parse_from([
            "chalk",
            "passwords",
            "generate",
            "--user",
            "user-001",
            "--force",
        ]);
        match cli.command {
            Commands::Passwords { action } => match action {
                PasswordsAction::Generate { user, force } => {
                    assert_eq!(user.as_deref(), Some("user-001"));
                    assert!(force);
                }
            },
            _ => panic!("expected Passwords command"),
        }
    }

    #[test]
    fn cli_parse_migrate_dry_run() {
        let cli = Cli::parse_from([
            "chalk",
            "migrate",
            "--from",
            "clever",
            "--path",
            "/tmp/export",
            "--dry-run",
        ]);
        match cli.command {
            Commands::Migrate {
                from,
                path,
                dry_run,
            } => {
                assert_eq!(from, "clever");
                assert_eq!(path, "/tmp/export");
                assert!(dry_run);
            }
            _ => panic!("expected Migrate command"),
        }
    }
}
