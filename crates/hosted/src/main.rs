//! Entry point for the multi-tenant `chalk-hosted` binary.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use chalk_hosted::commands;

#[derive(Parser, Debug)]
#[command(
    name = "chalk-hosted",
    version,
    about = "Chalk hosted multi-tenant runtime"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the multi-tenant Axum server.
    Serve {
        #[arg(long, default_value = "/etc/chalk-hosted/config.toml")]
        config: PathBuf,
    },
    /// Provision a new tenant: create the registry row and apply OSS migrations.
    Provision {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        admin_email: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        admin_name: Option<String>,
        #[arg(long, env = "POSTGRES_URL")]
        postgres_url: String,
    },
    /// Suspend a tenant; optionally drop its schema and registry row.
    Deprovision {
        #[arg(long)]
        slug: String,
        #[arg(long, env = "POSTGRES_URL")]
        postgres_url: String,
        #[arg(long, default_value_t = false)]
        purge_data: bool,
    },
    /// Re-run OSS migrations against every active tenant schema.
    MigrateAll {
        #[arg(long, env = "POSTGRES_URL")]
        postgres_url: String,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
    },
    /// Re-wrap every per-tenant sealed secret under a new master key.
    RotateMasterKey {
        #[arg(long, env = "POSTGRES_URL")]
        postgres_url: String,
        /// Old master key (base64). Defaults to env `MASTER_ENCRYPTION_KEY`.
        #[arg(long)]
        old_key: Option<String>,
        /// New master key (base64). If omitted, a fresh key is generated and
        /// printed to stdout — the operator must capture it before this
        /// process exits.
        #[arg(long)]
        new_key: Option<String>,
    },
    /// Tenant lifecycle administration.
    Tenant {
        #[command(subcommand)]
        cmd: TenantCmd,
    },
}

#[derive(Subcommand, Debug)]
enum TenantCmd {
    /// Mark an active tenant as suspended (blocks new logins).
    Suspend {
        #[arg(long)]
        slug: String,
        #[arg(long, env = "POSTGRES_URL")]
        postgres_url: String,
    },
    /// Mark a suspended tenant as active again.
    Unsuspend {
        #[arg(long)]
        slug: String,
        #[arg(long, env = "POSTGRES_URL")]
        postgres_url: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve { config } => commands::serve::run(&config).await,
        Cmd::Provision {
            slug,
            admin_email,
            display_name,
            admin_name,
            postgres_url,
        } => {
            commands::provision::run(commands::provision::ProvisionArgs {
                slug,
                admin_email,
                display_name,
                admin_name,
                postgres_url,
            })
            .await
        }
        Cmd::Deprovision {
            slug,
            postgres_url,
            purge_data,
        } => {
            commands::deprovision::run(commands::deprovision::DeprovisionArgs {
                slug,
                postgres_url,
                purge_data,
            })
            .await
        }
        Cmd::MigrateAll {
            postgres_url,
            concurrency,
        } => {
            commands::migrate_all::run(commands::migrate_all::MigrateAllArgs {
                postgres_url,
                concurrency,
            })
            .await
        }
        Cmd::RotateMasterKey {
            postgres_url,
            old_key,
            new_key,
        } => {
            commands::rotate_master_key::run(commands::rotate_master_key::RotateMasterKeyArgs {
                postgres_url,
                old_key,
                new_key,
            })
            .await
        }
        Cmd::Tenant { cmd } => match cmd {
            TenantCmd::Suspend { slug, postgres_url } => {
                commands::tenant::run_suspend(commands::tenant::SuspendArgs { slug, postgres_url })
                    .await
            }
            TenantCmd::Unsuspend { slug, postgres_url } => {
                commands::tenant::run_unsuspend(commands::tenant::UnsuspendArgs {
                    slug,
                    postgres_url,
                })
                .await
            }
        },
    }
}
