use anyhow::{bail, Context};
use futures_util::StreamExt;
use serde::Deserialize;
use std::io::Write;
use tracing::{info, warn};

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_API_URL: &str = "https://api.github.com/repos/usechalk/chalk/releases/latest";

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// Return the expected binary asset name for the current platform.
fn asset_name() -> anyhow::Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("chalk-x86_64-unknown-linux-gnu"),
        ("macos", "x86_64") => Ok("chalk-x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("chalk-aarch64-apple-darwin"),
        ("windows", "x86_64") => Ok("chalk-x86_64-pc-windows-msvc.exe"),
        (os, arch) => bail!("Unsupported platform: {os}/{arch}"),
    }
}

/// Run the `update` command.
///
/// When `check_only` is true, only report whether a newer version exists.
/// Otherwise, download the matching binary and replace the current executable.
pub async fn run(check_only: bool) -> anyhow::Result<()> {
    println!("Chalk v{CURRENT_VERSION}");
    println!("Checking for updates...");

    let release = match check_latest_release().await {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to check for updates: {e}");
            println!("Could not check for updates (are you offline?)");
            println!("Error: {e}");
            return Ok(());
        }
    };

    let latest = release.tag_name.trim_start_matches('v');
    if latest == CURRENT_VERSION {
        println!("You are running the latest version.");
        return Ok(());
    }

    println!("A new version is available: v{latest}");
    println!("Release: {}", release.html_url);

    if check_only {
        println!();
        println!("Run `chalk update` (without --check) to install.");
        return Ok(());
    }

    // --- self-update flow ---
    let expected = asset_name()?;
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == expected)
        .with_context(|| format!("No release asset found for this platform ({expected})"))?;

    println!("Downloading {expected}...");
    download_and_replace(&asset.browser_download_url).await?;
    println!("Updated to v{latest} successfully!");

    Ok(())
}

async fn check_latest_release() -> anyhow::Result<GitHubRelease> {
    let client = reqwest::Client::builder()
        .user_agent(format!("chalk/{CURRENT_VERSION}"))
        .build()?;

    info!("Checking GitHub for latest release");

    let release: GitHubRelease = client
        .get(GITHUB_API_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(release)
}

async fn download_and_replace(url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(format!("chalk/{CURRENT_VERSION}"))
        .build()?;

    let response = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .context("Failed to download release binary")?;

    // Stream to a temp file in the same directory as the current binary so the
    // rename is atomic (same filesystem).
    let current_exe =
        std::env::current_exe().context("Cannot determine current executable path")?;
    let exe_dir = current_exe
        .parent()
        .context("Current executable has no parent directory")?;

    let mut tmp = tempfile::NamedTempFile::new_in(exe_dir)
        .context("Failed to create temporary file for download")?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Error reading download stream")?;
        tmp.write_all(&chunk)
            .context("Error writing to temporary file")?;
    }
    tmp.flush()?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(tmp.path(), perms)
            .context("Failed to set executable permissions")?;
    }

    // Back up current binary
    let backup_path = exe_dir.join(".chalk.bak");
    std::fs::rename(&current_exe, &backup_path).context("Failed to back up current binary")?;

    // Move new binary into place
    if let Err(e) = std::fs::rename(tmp.path(), &current_exe) {
        // Attempt to restore backup on failure
        warn!("Failed to install new binary, restoring backup: {e}");
        let _ = std::fs::rename(&backup_path, &current_exe);
        bail!("Failed to install new binary: {e}");
    }

    // Clean up backup
    let _ = std::fs::remove_file(&backup_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_name_returns_valid_name() {
        // This test verifies the function succeeds on the current platform
        let name = asset_name().expect("asset_name should succeed on this platform");
        assert!(
            name.starts_with("chalk-"),
            "asset name should start with 'chalk-'"
        );
    }

    #[test]
    fn asset_name_matches_current_platform() {
        let name = asset_name().unwrap();
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;

        match (os, arch) {
            ("linux", "x86_64") => assert_eq!(name, "chalk-x86_64-unknown-linux-gnu"),
            ("macos", "x86_64") => assert_eq!(name, "chalk-x86_64-apple-darwin"),
            ("macos", "aarch64") => assert_eq!(name, "chalk-aarch64-apple-darwin"),
            ("windows", "x86_64") => assert_eq!(name, "chalk-x86_64-pc-windows-msvc.exe"),
            _ => panic!("unexpected platform: {os}/{arch}"),
        }
    }

    #[test]
    fn github_api_url_points_to_usechalk() {
        assert!(
            GITHUB_API_URL.contains("usechalk/chalk"),
            "API URL should point to usechalk org"
        );
    }
}
