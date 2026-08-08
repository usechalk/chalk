//! Microsoft Intune connector — Windows (and Apple) devices via the Graph API.
//!
//! Read-only: one token, one paged walk of
//! `/deviceManagement/managedDevices`, normalized into [`MdmDevice`]s. Auth is
//! the app-only client-credentials flow — a school registers an app, grants
//! `DeviceManagementManagedDevices.Read.All` as an application permission, and
//! pastes tenant id / client id / client secret into `chalk.toml`, the same
//! shape the AD sync uses for its bind credentials.
//!
//! **Validation caveat:** exercised against a mocked Graph API only. Nobody
//! has pointed this at a real Intune tenant yet, and nothing here should be
//! described as field-proven until somebody has.

use std::sync::Arc;

use async_trait::async_trait;
use chalk_core::config::IntuneConfig;
use chalk_core::error::{ChalkError, Result};
use chalk_core::models::asset::AssetType;
use serde::Deserialize;

use crate::mdm::{MdmConnector, MdmDevice, MdmSource};

pub struct IntuneConnector {
    config: IntuneConfig,
    http: reqwest::Client,
}

impl IntuneConnector {
    pub fn new(config: IntuneConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    fn login_base(&self) -> String {
        self.config
            .base_url
            .clone()
            .unwrap_or_else(|| "https://login.microsoftonline.com".to_string())
    }

    fn graph_base(&self) -> String {
        self.config
            .base_url
            .clone()
            .unwrap_or_else(|| "https://graph.microsoft.com".to_string())
    }

    async fn token(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.login_base(),
            self.config.tenant_id.trim()
        );
        let response = self
            .http
            .post(&url)
            .form(&[
                ("client_id", self.config.client_id.trim()),
                ("client_secret", self.config.client_secret.trim()),
                ("scope", "https://graph.microsoft.com/.default"),
                ("grant_type", "client_credentials"),
            ])
            .send()
            .await
            .map_err(|e| ChalkError::Sync(format!("Intune token request failed: {e}")))?;
        if !response.status().is_success() {
            // The status without the body: token error bodies can echo the
            // request, and a client secret does not belong in a log line.
            return Err(ChalkError::Sync(format!(
                "Intune token request was refused ({})",
                response.status()
            )));
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|e| ChalkError::Sync(format!("Intune token response unreadable: {e}")))?;
        Ok(token.access_token)
    }
}

/// One row of `managedDevices`, only the fields Chalk reads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedDevice {
    id: String,
    #[serde(default)]
    serial_number: Option<String>,
    #[serde(default)]
    manufacturer: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    os_version: Option<String>,
    #[serde(default)]
    operating_system: Option<String>,
    /// The enrolled user's UPN — an email in every school tenant.
    #[serde(default)]
    user_principal_name: Option<String>,
    #[serde(default)]
    email_address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DevicePage {
    #[serde(default)]
    value: Vec<ManagedDevice>,
    #[serde(rename = "@odata.nextLink", default)]
    next_link: Option<String>,
}

/// Intune's `operatingSystem` → Chalk's asset type. Windows machines are
/// laptops, Apple mobile devices are tablets, anything else is Other rather
/// than a guess.
fn asset_type_for(os: Option<&str>) -> AssetType {
    match os.map(|s| s.to_ascii_lowercase()) {
        Some(ref s) if s.contains("windows") => AssetType::Laptop,
        Some(ref s) if s.contains("ios") || s.contains("ipados") => AssetType::Tablet,
        Some(ref s) if s.contains("chrome") => AssetType::Chromebook,
        _ => AssetType::Other,
    }
}

fn to_mdm_device(d: ManagedDevice) -> MdmDevice {
    let user_email = d
        .user_principal_name
        .clone()
        .filter(|v| v.contains('@'))
        .or_else(|| d.email_address.clone().filter(|v| v.contains('@')));
    MdmDevice {
        external_id: d.id,
        serial_number: d.serial_number.filter(|s| !s.trim().is_empty()),
        asset_tag: None,
        make: d.manufacturer.filter(|s| !s.trim().is_empty()),
        model: d.model.filter(|s| !s.trim().is_empty()),
        os_version: d.os_version.filter(|s| !s.trim().is_empty()),
        user_email,
        asset_type: asset_type_for(d.operating_system.as_deref()),
    }
}

#[async_trait]
impl MdmConnector for IntuneConnector {
    fn source(&self) -> MdmSource {
        MdmSource::Intune
    }

    async fn fetch_devices(&self) -> Result<Vec<MdmDevice>> {
        let token = self.token().await?;
        let mut url = format!(
            "{}/v1.0/deviceManagement/managedDevices?$top=200",
            self.graph_base()
        );
        let mut out = Vec::new();
        loop {
            let response = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| ChalkError::Sync(format!("Intune device list failed: {e}")))?;
            if !response.status().is_success() {
                return Err(ChalkError::Sync(format!(
                    "Intune device list was refused ({})",
                    response.status()
                )));
            }
            let page: DevicePage = response
                .json()
                .await
                .map_err(|e| ChalkError::Sync(format!("Intune device page unreadable: {e}")))?;
            out.extend(page.value.into_iter().map(to_mdm_device));
            match page.next_link {
                // Graph returns absolute next links; in tests the mock does
                // too, so no rebasing is needed in either world.
                Some(next) => url = next,
                None => break,
            }
        }
        Ok(out)
    }
}

/// Build the connector the CLI and job handler share.
pub fn connector(config: IntuneConfig) -> Arc<dyn MdmConnector> {
    Arc::new(IntuneConnector::new(config))
}

#[cfg(test)]
mod tests;
