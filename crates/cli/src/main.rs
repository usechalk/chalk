use clap::Parser;
use tracing_subscriber::EnvFilter;

mod commands;

#[derive(Parser)]
#[command(name = "chalk", about = "K-12 SIS integration platform", version)]
struct Cli {
    /// Path to configuration file. When omitted, chalk searches:
    ///   1. ./chalk.toml (current directory)
    ///   2. <default-data-dir>/chalk.toml — where `chalk init` writes
    ///      its config:
    ///       - Windows: %LOCALAPPDATA%\chalk\chalk.toml
    ///       - macOS:   ~/Library/Application Support/chalk/chalk.toml
    ///       - Linux:   /var/lib/chalk/chalk.toml
    #[arg(long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

/// Resolve the config path: explicit `--config` wins; otherwise probe
/// CWD and the platform default data-dir for a `chalk.toml`. Returns
/// an `anyhow::Error` listing the locations searched when nothing is
/// found — the previous default-value behavior would silently fail
/// downstream with a confusing "file not found" on whatever the cwd
/// happened to be, especially on Windows where the user ran
/// `chalk init` (which now writes under `%LOCALAPPDATA%\chalk`).
fn resolve_config_path(arg: Option<&str>) -> anyhow::Result<String> {
    if let Some(explicit) = arg {
        return Ok(explicit.to_string());
    }
    let mut tried = Vec::new();
    let cwd_path = std::path::PathBuf::from("chalk.toml");
    tried.push(cwd_path.display().to_string());
    if cwd_path.exists() {
        return Ok("chalk.toml".to_string());
    }
    let default_dir = commands::init::default_data_dir();
    let default_path = std::path::PathBuf::from(&default_dir).join("chalk.toml");
    tried.push(default_path.display().to_string());
    if default_path.exists() {
        return Ok(default_path.display().to_string());
    }
    anyhow::bail!(
        "could not find chalk.toml. Tried:\n  - {}\n\nRun `chalk init` to create one, or pass `--config <path>`.",
        tried.join("\n  - ")
    )
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Initialize Chalk data directory and configuration
    Init {
        /// Data directory path. Defaults to a platform-appropriate location:
        /// `%LOCALAPPDATA%\chalk` on Windows, `~/Library/Application Support/chalk`
        /// on macOS, `/var/lib/chalk` on Linux/other.
        #[arg(long)]
        data_dir: Option<String>,
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
    /// Webhook operator subcommands.
    Webhook {
        #[command(subcommand)]
        action: WebhookAction,
    },
    /// Sync roster data to Active Directory via LDAP
    AdSync {
        /// Preview changes without applying
        #[arg(long)]
        dry_run: bool,
        /// Force full resync of all users
        #[arg(long)]
        full: bool,
        /// Export initial passwords for newly created accounts
        #[arg(long)]
        export_passwords: bool,
        /// Show the status of the last sync run
        #[arg(long)]
        status: bool,
        /// Test the LDAP connection without syncing
        #[arg(long)]
        test_connection: bool,
    },
}

#[derive(clap::Subcommand)]
enum WebhookAction {
    /// Drain the webhook retry queue. Runs `process_pending_retries` until
    /// `--iterations` ticks have elapsed (default: 1), sleeping
    /// `--interval-secs` between ticks. Intended for ops + E2E tests.
    RetryPending {
        /// Number of retry ticks to run; omit for an indefinite loop.
        #[arg(long)]
        iterations: Option<u32>,
        /// Sleep between ticks, in seconds.
        #[arg(long, default_value = "5")]
        interval_secs: u64,
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

    // Init writes the config file itself and Update doesn't load one,
    // so neither command needs a resolved path. Every other command
    // resolves up front so a missing config produces one clear error
    // instead of a downstream "file not found" further in.
    let needs_config = !matches!(cli.command, Commands::Init { .. } | Commands::Update { .. });
    let config_path = if needs_config {
        resolve_config_path(cli.config.as_deref())?
    } else {
        String::new()
    };

    match cli.command {
        Commands::Init { data_dir, provider } => {
            let resolved = data_dir.unwrap_or_else(commands::init::default_data_dir);
            commands::init::run(&resolved, &provider).await?;
        }
        Commands::Sync { dry_run } => {
            commands::sync::run(&config_path, dry_run).await?;
        }
        Commands::Status => {
            commands::status::run(&config_path).await?;
        }
        Commands::Update { check } => {
            commands::update::run(check).await?;
        }
        Commands::Serve { port } => {
            commands::serve::run(&config_path, port).await?;
        }
        Commands::GoogleSync { dry_run } => {
            commands::google_sync::run(&config_path, dry_run).await?;
        }
        Commands::Import { dir, dry_run } => {
            commands::import::run(&config_path, &dir, dry_run).await?;
        }
        Commands::Export { dir } => {
            commands::export::run(&config_path, &dir).await?;
        }
        Commands::Passwords { action } => match action {
            PasswordsAction::Generate { user, force } => {
                commands::passwords::run(&config_path, user.as_deref(), force).await?;
            }
        },
        Commands::Migrate {
            from,
            path,
            dry_run,
        } => {
            commands::migrate::run(&config_path, &from, &path, dry_run).await?;
        }
        Commands::Webhook { action } => match action {
            WebhookAction::RetryPending {
                iterations,
                interval_secs,
            } => {
                commands::webhook::retry_pending(
                    &config_path,
                    iterations,
                    std::time::Duration::from_secs(interval_secs),
                )
                .await?;
            }
        },
        Commands::AdSync {
            dry_run,
            full,
            export_passwords,
            status,
            test_connection,
        } => {
            commands::ad_sync::run(
                &config_path,
                dry_run,
                full,
                export_passwords,
                status,
                test_connection,
            )
            .await?;
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
        assert!(cli.config.is_none());
        match cli.command {
            Commands::Init { data_dir, provider } => {
                // Now resolved at runtime — clap leaves it `None`.
                assert!(data_dir.is_none());
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
        assert_eq!(cli.config.as_deref(), Some("/etc/chalk.toml"));
        match cli.command {
            Commands::Init { data_dir, provider } => {
                assert_eq!(data_dir.as_deref(), Some("/opt/chalk"));
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
    fn cli_parse_webhook_retry_pending() {
        let cli = Cli::parse_from([
            "chalk",
            "webhook",
            "retry-pending",
            "--iterations",
            "3",
            "--interval-secs",
            "1",
        ]);
        match cli.command {
            Commands::Webhook { action } => match action {
                WebhookAction::RetryPending {
                    iterations,
                    interval_secs,
                } => {
                    assert_eq!(iterations, Some(3));
                    assert_eq!(interval_secs, 1);
                }
            },
            _ => panic!("expected Webhook command"),
        }
    }

    #[test]
    fn cli_parse_webhook_retry_pending_defaults_infinite_loop() {
        let cli = Cli::parse_from(["chalk", "webhook", "retry-pending"]);
        match cli.command {
            Commands::Webhook { action } => match action {
                WebhookAction::RetryPending {
                    iterations,
                    interval_secs,
                } => {
                    assert_eq!(iterations, None);
                    assert_eq!(interval_secs, 5);
                }
            },
            _ => panic!("expected Webhook command"),
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
    fn cli_parse_ad_sync_defaults() {
        let cli = Cli::parse_from(["chalk", "ad-sync"]);
        match cli.command {
            Commands::AdSync {
                dry_run,
                full,
                export_passwords,
                status,
                test_connection,
            } => {
                assert!(!dry_run);
                assert!(!full);
                assert!(!export_passwords);
                assert!(!status);
                assert!(!test_connection);
            }
            _ => panic!("expected AdSync command"),
        }
    }

    #[test]
    fn cli_parse_ad_sync_dry_run() {
        let cli = Cli::parse_from(["chalk", "ad-sync", "--dry-run"]);
        match cli.command {
            Commands::AdSync { dry_run, .. } => {
                assert!(dry_run);
            }
            _ => panic!("expected AdSync command"),
        }
    }

    #[test]
    fn cli_parse_ad_sync_status() {
        let cli = Cli::parse_from(["chalk", "ad-sync", "--status"]);
        match cli.command {
            Commands::AdSync { status, .. } => {
                assert!(status);
            }
            _ => panic!("expected AdSync command"),
        }
    }

    #[test]
    fn cli_parse_ad_sync_test_connection() {
        let cli = Cli::parse_from(["chalk", "ad-sync", "--test-connection"]);
        match cli.command {
            Commands::AdSync {
                test_connection, ..
            } => {
                assert!(test_connection);
            }
            _ => panic!("expected AdSync command"),
        }
    }

    #[test]
    fn cli_parse_ad_sync_all_flags() {
        let cli = Cli::parse_from([
            "chalk",
            "ad-sync",
            "--dry-run",
            "--full",
            "--export-passwords",
        ]);
        match cli.command {
            Commands::AdSync {
                dry_run,
                full,
                export_passwords,
                ..
            } => {
                assert!(dry_run);
                assert!(full);
                assert!(export_passwords);
            }
            _ => panic!("expected AdSync command"),
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
