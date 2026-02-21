use serde::Deserialize;
use tracing::{info, warn};

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
}

/// Run the `update` command: check GitHub for the latest release.
pub async fn run() -> anyhow::Result<()> {
    println!("Chalk v{}", CURRENT_VERSION);
    println!("Checking for updates...");

    match check_latest_release().await {
        Ok(release) => {
            let latest = release.tag_name.trim_start_matches('v');
            if latest == CURRENT_VERSION {
                println!("You are running the latest version.");
            } else {
                println!("A new version is available: v{}", latest);
                println!("Download: {}", release.html_url);
                println!();
                println!("To update, download the latest release from the URL above.");
            }
        }
        Err(e) => {
            warn!("Failed to check for updates: {}", e);
            println!("Could not check for updates (are you offline?)");
            println!("Error: {}", e);
        }
    }

    Ok(())
}

async fn check_latest_release() -> anyhow::Result<GitHubRelease> {
    let client = reqwest::Client::builder()
        .user_agent(format!("chalk/{}", CURRENT_VERSION))
        .build()?;

    info!("Checking GitHub for latest release");

    let release: GitHubRelease = client
        .get("https://api.github.com/repos/anthropics/chalk/releases/latest")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(release)
}
