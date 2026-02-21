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
    /// Check for updates
    Update,
    /// Start the admin console web server
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,
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
        Commands::Update => {
            commands::update::run().await?;
        }
        Commands::Serve { port } => {
            commands::serve::run(&cli.config, port).await?;
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
        assert!(matches!(cli.command, Commands::Update));
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
}
