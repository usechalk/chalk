use std::path::Path;
use std::sync::Arc;

use axum::http::HeaderValue;
use chalk_core::config::{ChalkConfig, DatabaseDriver};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_idp::routes::{router as idp_router, IdpState};
use tokio::net::TcpListener;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

/// Run the `serve` command: start the admin console web server.
pub async fn run(config_path: &str, port: u16) -> anyhow::Result<()> {
    let config = ChalkConfig::load(Path::new(config_path))?;
    config.validate()?;

    let pool = match config.chalk.database.driver {
        DatabaseDriver::Sqlite => {
            let path = config
                .chalk
                .database
                .path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("SQLite path not configured"))?;
            let connect_str = format!("sqlite:{}?mode=rwc", path);
            DatabasePool::new_sqlite(&connect_str).await?
        }
        DatabaseDriver::Postgres => {
            anyhow::bail!("PostgreSQL is not yet supported");
        }
    };

    let repo = match pool {
        DatabasePool::Sqlite(p) => SqliteRepository::new(p),
    };
    let repo = Arc::new(repo);

    let state = Arc::new(chalk_console::AppState {
        repo: repo.clone(),
        config: config.clone(),
    });
    let mut app = chalk_console::router(state);

    if config.idp.enabled {
        let idp_state = Arc::new(IdpState {
            repo: repo.clone(),
            config: config.clone(),
        });
        app = app.nest("/idp", idp_router(idp_state));
        info!("IDP routes mounted at /idp");
    }

    // Add security headers
    let app = app
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ));

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;

    println!("Chalk admin console listening on http://{}", addr);
    info!("Starting server on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
    info!("Received shutdown signal");
}
