//! Jamf Pro connector — iPads (mobile devices) via the Jamf Pro API.
//!
//! Read-only: an OAuth client-credentials token from `/api/oauth/token`, then
//! a paged walk of `/api/v2/mobile-devices`, normalized into [`MdmDevice`]s.
//! A school creates an API client with the Mobile Devices read privilege and
//! pastes its server URL, client id and client secret into `chalk.toml`.
//!
//! **Validation caveat:** exercised against a mocked Jamf API only. Nobody has
//! pointed this at a real Jamf instance yet, and nothing here should be
//! described as field-proven until somebody has.

use std::sync::Arc;

use async_trait::async_trait;
use chalk_core::config::JamfConfig;
use chalk_core::error::{ChalkError, Result};
use chalk_core::models::asset::AssetType;
use serde::Deserialize;

use crate::mdm::{MdmConnector, MdmDevice, MdmSource};

pub struct JamfConnector {
    config: JamfConfig,
    http: reqwest::Client,
}

impl JamfConnector {
    pub fn new(config: JamfConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    fn base(&self) -> String {
        self.config.url.trim().trim_end_matches('/').to_string()
    }

    async fn token(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }
        let response = self
            .http
            .post(format!("{}/api/oauth/token", self.base()))
            .form(&[
                ("client_id", self.config.client_id.trim()),
                ("client_secret", self.config.client_secret.trim()),
                ("grant_type", "client_credentials"),
            ])
            .send()
            .await
            .map_err(|e| ChalkError::Sync(format!("Jamf token request failed: {e}")))?;
        if !response.status().is_success() {
            return Err(ChalkError::Sync(format!(
                "Jamf token request was refused ({})",
                response.status()
            )));
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|e| ChalkError::Sync(format!("Jamf token response unreadable: {e}")))?;
        Ok(token.access_token)
    }
}

/// One row of `/api/v2/mobile-devices`, only the fields Chalk reads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JamfMobileDevice {
    id: String,
    #[serde(default)]
    serial_number: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    os_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JamfPage {
    #[serde(default)]
    total_count: i64,
    #[serde(default)]
    results: Vec<JamfMobileDevice>,
}

fn to_mdm_device(d: JamfMobileDevice) -> MdmDevice {
    MdmDevice {
        external_id: d.id,
        serial_number: d.serial_number.filter(|s| !s.trim().is_empty()),
        asset_tag: None,
        make: Some("Apple".to_string()),
        model: d.model.filter(|s| !s.trim().is_empty()),
        os_version: d.os_version.filter(|s| !s.trim().is_empty()),
        // Jamf's `username` is only usable when it is actually an email — the
        // engine matches exact roster addresses and nothing else.
        user_email: d.username.filter(|u| u.contains('@')),
        asset_type: AssetType::Tablet,
    }
}

#[async_trait]
impl MdmConnector for JamfConnector {
    fn source(&self) -> MdmSource {
        MdmSource::Jamf
    }

    async fn fetch_devices(&self) -> Result<Vec<MdmDevice>> {
        let token = self.token().await?;
        let mut out = Vec::new();
        let mut page = 0usize;
        loop {
            let url = format!(
                "{}/api/v2/mobile-devices?page={}&page-size=200",
                self.base(),
                page
            );
            let response = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| ChalkError::Sync(format!("Jamf device list failed: {e}")))?;
            if !response.status().is_success() {
                return Err(ChalkError::Sync(format!(
                    "Jamf device list was refused ({})",
                    response.status()
                )));
            }
            let body: JamfPage = response
                .json()
                .await
                .map_err(|e| ChalkError::Sync(format!("Jamf device page unreadable: {e}")))?;
            let got = body.results.len();
            out.extend(body.results.into_iter().map(to_mdm_device));
            // Jamf pages by count: stop when we have them all or a page comes
            // back empty (defensive — a lying total must not loop forever).
            if got == 0 || out.len() as i64 >= body.total_count {
                break;
            }
            page += 1;
        }
        Ok(out)
    }
}

/// Build the connector the CLI and job handler share.
pub fn connector(config: JamfConfig) -> Arc<dyn MdmConnector> {
    Arc::new(JamfConnector::new(config))
}

#[cfg(test)]
mod tests;
