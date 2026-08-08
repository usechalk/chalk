//! Entra ID (Azure AD) user provisioning over the Microsoft Graph API —
//! the cloud sibling of the LDAP sync in [`crate::sync`], sharing its
//! operational discipline: a run row around every sync, per-user state with
//! a field hash so unchanged users cost nothing, and departures disabled
//! rather than deleted.
//!
//! **Validation caveat:** exercised against a mocked Graph API only. Nobody
//! has pointed this at a real Entra tenant yet, and nothing here should be
//! described as field-proven until somebody has.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chalk_core::config::EntraConfig;
use chalk_core::db::repository::ChalkRepository;
use chalk_core::error::{ChalkError, Result};
use chalk_core::models::common::Status;
use chalk_core::models::entra::{EntraRunStatus, EntraSyncStatus, EntraUserState};
use chalk_core::models::sync::UserFilter;
use chalk_core::models::user::User;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use crate::sync::compute_field_hash;

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntraSummary {
    pub users_created: i64,
    pub users_updated: i64,
    pub users_disabled: i64,
    pub users_skipped: i64,
    pub errors: i64,
    pub error_details: Option<String>,
}

// ---------------------------------------------------------------------------
// Graph client
// ---------------------------------------------------------------------------

/// A minimal Graph client for `/users`: token, lookup, create, patch.
pub struct GraphClient {
    config: EntraConfig,
    http: reqwest::Client,
}

/// An existing Graph account, as much of it as the sync reads.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphUser {
    pub id: String,
    #[serde(default)]
    pub account_enabled: Option<bool>,
}

impl GraphClient {
    pub fn new(config: EntraConfig) -> Self {
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
            .map_err(|e| ChalkError::Sync(format!("Entra token request failed: {e}")))?;
        if !response.status().is_success() {
            // The status without the body: token error bodies can echo the
            // request, and a client secret does not belong in a log line.
            return Err(ChalkError::Sync(format!(
                "Entra token request was refused ({})",
                response.status()
            )));
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|e| ChalkError::Sync(format!("Entra token response unreadable: {e}")))?;
        Ok(token.access_token)
    }

    /// Look one account up by UPN. `Ok(None)` when Graph has never heard of
    /// it — the signal to create.
    pub async fn get_user_by_upn(&self, token: &str, upn: &str) -> Result<Option<GraphUser>> {
        let url = format!(
            "{}/v1.0/users/{}?$select=id,accountEnabled",
            self.graph_base(),
            upn
        );
        let response = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ChalkError::Sync(format!("Entra user lookup failed: {e}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(ChalkError::Sync(format!(
                "Entra user lookup was refused ({})",
                response.status()
            )));
        }
        let user: GraphUser = response
            .json()
            .await
            .map_err(|e| ChalkError::Sync(format!("Entra user response unreadable: {e}")))?;
        Ok(Some(user))
    }

    /// Create one account, initially enabled, with a random single-use
    /// password the user must change at first sign-in.
    pub async fn create_user(&self, token: &str, user: &User, upn: &str) -> Result<GraphUser> {
        let url = format!("{}/v1.0/users", self.graph_base());
        let body = json!({
            "accountEnabled": true,
            "displayName": format!("{} {}", user.given_name, user.family_name),
            "givenName": user.given_name,
            "surname": user.family_name,
            "mailNickname": upn.split('@').next().unwrap_or(upn),
            "userPrincipalName": upn,
            "passwordProfile": {
                // Random, never stored, never shown: the account is expected
                // to be used through SSO, and a first-sign-in reset covers
                // the rest.
                "password": format!("Ch@{}", uuid::Uuid::new_v4()),
                "forceChangePasswordNextSignIn": true,
            },
        });
        let response = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ChalkError::Sync(format!("Entra user create failed: {e}")))?;
        if !response.status().is_success() {
            return Err(ChalkError::Sync(format!(
                "Entra refused to create {upn} ({})",
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|e| ChalkError::Sync(format!("Entra create response unreadable: {e}")))
    }

    /// Update the name fields on an existing account.
    pub async fn update_user(&self, token: &str, object_id: &str, user: &User) -> Result<()> {
        self.patch(
            token,
            object_id,
            json!({
                "displayName": format!("{} {}", user.given_name, user.family_name),
                "givenName": user.given_name,
                "surname": user.family_name,
            }),
        )
        .await
    }

    /// Disable sign-in without deleting anything.
    pub async fn disable_user(&self, token: &str, object_id: &str) -> Result<()> {
        self.patch(token, object_id, json!({ "accountEnabled": false }))
            .await
    }

    async fn patch(&self, token: &str, object_id: &str, body: serde_json::Value) -> Result<()> {
        let url = format!("{}/v1.0/users/{}", self.graph_base(), object_id);
        let response = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ChalkError::Sync(format!("Entra user update failed: {e}")))?;
        if !response.status().is_success() {
            return Err(ChalkError::Sync(format!(
                "Entra refused the update ({})",
                response.status()
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct EntraSyncEngine<R: ChalkRepository + ?Sized> {
    repo: Arc<R>,
    client: GraphClient,
    config: EntraConfig,
}

impl<R: ChalkRepository + ?Sized> EntraSyncEngine<R> {
    pub fn new(repo: Arc<R>, client: GraphClient, config: EntraConfig) -> Self {
        Self {
            repo,
            client,
            config,
        }
    }

    /// Run a delta sync, wrapped in a run row like the AD sync's.
    pub async fn run_sync(&self, dry_run: bool) -> Result<EntraSummary> {
        let run = self.repo.create_entra_sync_run(dry_run).await?;
        info!(run_id = %run.id, dry_run, "starting Entra sync");
        match self.execute(dry_run).await {
            Ok(summary) => {
                self.repo
                    .update_entra_sync_run(
                        &run.id,
                        EntraRunStatus::Completed,
                        summary.users_created,
                        summary.users_updated,
                        summary.users_disabled,
                        summary.users_skipped,
                        summary.errors,
                        summary.error_details.as_deref(),
                    )
                    .await?;
                info!(
                    run_id = %run.id,
                    created = summary.users_created,
                    updated = summary.users_updated,
                    disabled = summary.users_disabled,
                    skipped = summary.users_skipped,
                    errors = summary.errors,
                    "Entra sync completed"
                );
                Ok(summary)
            }
            Err(e) => {
                self.repo
                    .update_entra_sync_run(
                        &run.id,
                        EntraRunStatus::Failed,
                        0,
                        0,
                        0,
                        0,
                        0,
                        Some(&e.to_string()),
                    )
                    .await?;
                Err(e)
            }
        }
    }

    /// The UPN a roster user provisions under: their roster username,
    /// lowercased, at the configured domain.
    fn upn_for(&self, user: &User) -> String {
        format!(
            "{}@{}",
            user.username.trim().to_lowercase(),
            self.config.domain.trim()
        )
    }

    async fn execute(&self, dry_run: bool) -> Result<EntraSummary> {
        if self.config.domain.trim().is_empty() {
            return Err(ChalkError::Sync("entra.domain is not configured".into()));
        }
        let all_users = self.repo.list_users(&UserFilter::default()).await?;
        let active: Vec<&User> = all_users
            .iter()
            .filter(|u| u.status == Status::Active && u.enabled_user)
            .collect();
        let active_ids: HashSet<&str> = active.iter().map(|u| u.sourced_id.as_str()).collect();

        let states = self.repo.list_entra_sync_states().await?;
        let state_map: HashMap<&str, &EntraUserState> = states
            .iter()
            .map(|s| (s.user_sourced_id.as_str(), s))
            .collect();

        // One token for the whole run; dry runs never contact anything.
        let token = if dry_run {
            String::new()
        } else {
            self.client.token().await?
        };

        let mut summary = EntraSummary::default();
        let mut error_lines: Vec<String> = Vec::new();
        let now = Utc::now();

        for user in &active {
            let field_hash = compute_field_hash(user);
            let upn = self.upn_for(user);
            match state_map.get(user.sourced_id.as_str()) {
                // Known and unchanged: free.
                Some(state)
                    if state.field_hash == field_hash
                        && state.sync_status == EntraSyncStatus::Synced =>
                {
                    summary.users_skipped += 1;
                }
                // Known and changed (or previously errored): update.
                Some(state) => {
                    summary.users_updated += 1;
                    if dry_run {
                        continue;
                    }
                    match self
                        .client
                        .update_user(&token, &state.entra_object_id, user)
                        .await
                    {
                        Ok(()) => {
                            self.save_state(user, &state.entra_object_id, &upn, &field_hash, now)
                                .await?;
                        }
                        Err(e) => {
                            summary.users_updated -= 1;
                            self.record_error(
                                user,
                                &state.entra_object_id,
                                &e,
                                &mut summary,
                                &mut error_lines,
                            )
                            .await?;
                        }
                    }
                }
                // Unknown: adopt an existing account by UPN, or create one.
                None => {
                    summary.users_created += 1;
                    if dry_run {
                        continue;
                    }
                    let result = async {
                        match self.client.get_user_by_upn(&token, &upn).await? {
                            Some(existing) => {
                                // Adoption: the account exists (hand-made or
                                // from a previous tool); update it in place
                                // rather than colliding on create.
                                self.client.update_user(&token, &existing.id, user).await?;
                                Ok::<String, ChalkError>(existing.id)
                            }
                            None => {
                                let created = self.client.create_user(&token, user, &upn).await?;
                                Ok(created.id)
                            }
                        }
                    }
                    .await;
                    match result {
                        Ok(object_id) => {
                            self.save_state(user, &object_id, &upn, &field_hash, now)
                                .await?;
                        }
                        Err(e) => {
                            summary.users_created -= 1;
                            self.record_error(user, "", &e, &mut summary, &mut error_lines)
                                .await?;
                        }
                    }
                }
            }
        }

        // Departures: state exists, roster no longer active — disable, once.
        for state in &states {
            if active_ids.contains(state.user_sourced_id.as_str())
                || state.sync_status == EntraSyncStatus::Disabled
            {
                continue;
            }
            summary.users_disabled += 1;
            if dry_run {
                continue;
            }
            match self
                .client
                .disable_user(&token, &state.entra_object_id)
                .await
            {
                Ok(()) => {
                    let mut s = (*state).clone();
                    s.sync_status = EntraSyncStatus::Disabled;
                    s.last_synced_at = Some(now);
                    s.updated_at = now;
                    self.repo.upsert_entra_sync_state(&s).await?;
                }
                Err(e) => {
                    summary.users_disabled -= 1;
                    summary.errors += 1;
                    warn!(user = %state.user_sourced_id, "Entra disable failed: {e}");
                    error_lines.push(format!("{}: {e}", state.user_sourced_id));
                }
            }
        }

        if !error_lines.is_empty() {
            summary.error_details = Some(error_lines.join("\n"));
        }
        Ok(summary)
    }

    async fn save_state(
        &self,
        user: &User,
        object_id: &str,
        upn: &str,
        field_hash: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<()> {
        self.repo
            .upsert_entra_sync_state(&EntraUserState {
                user_sourced_id: user.sourced_id.clone(),
                entra_object_id: object_id.to_string(),
                upn: upn.to_string(),
                field_hash: field_hash.to_string(),
                sync_status: EntraSyncStatus::Synced,
                last_synced_at: Some(now),
                created_at: now,
                updated_at: now,
            })
            .await
    }

    async fn record_error(
        &self,
        user: &User,
        known_object_id: &str,
        e: &ChalkError,
        summary: &mut EntraSummary,
        error_lines: &mut Vec<String>,
    ) -> Result<()> {
        summary.errors += 1;
        warn!(user = %user.sourced_id, "Entra sync error: {e}");
        error_lines.push(format!("{}: {e}", user.sourced_id));
        // An errored user keeps (or gains) an Error state with an *empty
        // hash*, so the next run retries instead of skipping on a stale one.
        // A known object id is preserved — losing it would turn the retry
        // into a duplicate-account attempt.
        let now = Utc::now();
        self.repo
            .upsert_entra_sync_state(&EntraUserState {
                user_sourced_id: user.sourced_id.clone(),
                entra_object_id: known_object_id.to_string(),
                upn: self.upn_for(user),
                field_hash: String::new(),
                sync_status: EntraSyncStatus::Error,
                last_synced_at: None,
                created_at: now,
                updated_at: now,
            })
            .await
    }
}

#[cfg(test)]
mod tests;
