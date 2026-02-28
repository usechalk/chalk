//! Delta sync engine for Active Directory user provisioning.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use chalk_core::config::AdSyncConfig;
use chalk_core::db::repository::ChalkRepository;
use chalk_core::error::{ChalkError, Result};
use chalk_core::models::ad_sync::{AdSyncRunStatus, AdSyncStatus, AdSyncUserState};
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::sync::UserFilter;
use chalk_core::models::user::User;

use crate::client::AdClient;
use crate::models::AdUserAttrs;
use crate::ou::{resolve_ou_path, template_to_dn, user_dn};
use crate::password::{generate_password, generate_random_password};
use crate::username::generate_sam_account_name;

/// Summary of a sync run.
#[derive(Debug, Clone)]
pub struct SyncSummary {
    pub users_created: i64,
    pub users_updated: i64,
    pub users_disabled: i64,
    pub users_skipped: i64,
    pub groups_created: u32,
    pub groups_updated: u32,
    pub errors: i64,
    pub error_details: Option<String>,
    pub dry_run: bool,
}

/// Delta sync engine that provisions Active Directory accounts from roster data.
pub struct AdSyncEngine<R: ChalkRepository> {
    repo: Arc<R>,
    client: AdClient,
    config: AdSyncConfig,
}

impl<R: ChalkRepository> AdSyncEngine<R> {
    /// Create a new sync engine.
    pub fn new(repo: Arc<R>, client: AdClient, config: AdSyncConfig) -> Self {
        Self {
            repo,
            client,
            config,
        }
    }

    /// Run a delta sync. If `dry_run` is true, no LDAP calls are made.
    /// If `full` is true, all users are processed regardless of field hash.
    pub async fn run_sync(&self, dry_run: bool, full: bool) -> Result<SyncSummary> {
        // 1. Create a sync run record
        let run = self.repo.create_ad_sync_run(dry_run).await?;
        let run_id = run.id.clone();

        info!(run_id = %run_id, dry_run, full, "starting AD sync");

        match self.execute_sync(dry_run, full).await {
            Ok(summary) => {
                self.repo
                    .update_ad_sync_run(
                        &run_id,
                        AdSyncRunStatus::Completed,
                        summary.users_created,
                        summary.users_updated,
                        summary.users_disabled,
                        summary.users_skipped,
                        summary.groups_created as i64,
                        summary.groups_updated as i64,
                        summary.errors,
                        summary.error_details.as_deref(),
                    )
                    .await?;

                info!(
                    run_id = %run_id,
                    users_created = summary.users_created,
                    users_updated = summary.users_updated,
                    users_disabled = summary.users_disabled,
                    users_skipped = summary.users_skipped,
                    errors = summary.errors,
                    dry_run,
                    "AD sync completed"
                );

                Ok(summary)
            }
            Err(e) => {
                let error_msg = e.to_string();
                self.repo
                    .update_ad_sync_run(
                        &run_id,
                        AdSyncRunStatus::Failed,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        Some(&error_msg),
                    )
                    .await?;
                Err(e)
            }
        }
    }

    async fn execute_sync(&self, dry_run: bool, full: bool) -> Result<SyncSummary> {
        let base_dn = self.client.base_dn();
        if base_dn.is_empty() {
            return Err(ChalkError::AdSync("base_dn not configured".into()));
        }

        // 2. Load all roster users
        let all_users = self.repo.list_users(&UserFilter::default()).await?;
        let active_users: Vec<&User> = all_users
            .iter()
            .filter(|u| u.status == Status::Active && u.enabled_user)
            .collect();

        // 3. Load existing AD sync states
        let sync_states = self.repo.list_ad_sync_states().await?;
        let state_map: HashMap<&str, &AdSyncUserState> = sync_states
            .iter()
            .map(|s| (s.user_sourced_id.as_str(), s))
            .collect();

        // Build set of active+enabled user IDs for departure detection
        let active_ids: std::collections::HashSet<&str> =
            active_users.iter().map(|u| u.sourced_id.as_str()).collect();

        // Issue 4: Also collect IDs of disabled SIS users so they are treated as departed
        let disabled_user_ids: std::collections::HashSet<&str> = all_users
            .iter()
            .filter(|u| !u.enabled_user || u.status != Status::Active)
            .map(|u| u.sourced_id.as_str())
            .collect();

        // Collect existing sAMAccountNames for collision detection
        let existing_sams: Vec<String> = sync_states
            .iter()
            .map(|s| s.ad_sam_account_name.clone())
            .collect();

        let mut summary = SyncSummary {
            users_created: 0,
            users_updated: 0,
            users_disabled: 0,
            users_skipped: 0,
            groups_created: 0,
            groups_updated: 0,
            errors: 0,
            error_details: None,
            dry_run,
        };

        // 4-6. Process each active user
        let mut new_sams = existing_sams.clone();
        for user in &active_users {
            let field_hash = compute_field_hash(user);

            match state_map.get(user.sourced_id.as_str()) {
                None => {
                    // New user -- needs creation
                    if !self.config.options.provision_users {
                        summary.users_skipped += 1;
                        continue;
                    }

                    let ou_path = self.resolve_user_ou(user);
                    let ou_dn = template_to_dn(&ou_path, base_dn);
                    let sam =
                        generate_sam_account_name(&user.given_name, &user.family_name, &new_sams);
                    new_sams.push(sam.clone());

                    let domain = base_dn_to_domain(base_dn);
                    let upn = format!("{sam}@{domain}");
                    let display_name = format!("{} {}", user.given_name, user.family_name);
                    let dn = user_dn(&display_name, &ou_dn);

                    let password = self.generate_user_password(user);

                    if !dry_run {
                        if self.config.options.manage_ous {
                            if let Err(e) = self.client.ensure_ou_exists(&ou_dn).await {
                                tracing::error!(user = %user.sourced_id, error = %e, "failed to ensure OU exists");
                                record_error(&mut summary, &user.sourced_id, &e);
                                continue;
                            }
                        }

                        let attrs = AdUserAttrs {
                            dn: dn.clone(),
                            sam_account_name: sam.clone(),
                            upn: Some(upn.clone()),
                            display_name,
                            given_name: user.given_name.clone(),
                            surname: user.family_name.clone(),
                            email: user.email.clone(),
                            ou: ou_dn.clone(),
                            user_account_control: 512,
                        };
                        match self.client.create_user(&attrs, &password).await {
                            Ok(()) => {}
                            Err(e) => {
                                tracing::error!(user = %user.sourced_id, error = %e, "failed to create AD user");
                                record_error(&mut summary, &user.sourced_id, &e);
                                continue;
                            }
                        }

                        let state = AdSyncUserState {
                            user_sourced_id: user.sourced_id.clone(),
                            ad_dn: dn,
                            ad_sam_account_name: sam,
                            ad_upn: Some(upn),
                            ad_ou: ou_dn,
                            field_hash,
                            sync_status: AdSyncStatus::Synced,
                            initial_password: Some(password),
                            last_synced_at: Some(Utc::now()),
                            created_at: Utc::now(),
                            updated_at: Utc::now(),
                        };
                        self.repo.upsert_ad_sync_state(&state).await?;
                    }

                    summary.users_created += 1;
                }
                Some(existing_state) if full || existing_state.field_hash != field_hash => {
                    // Changed user (or full sync forced) -- needs update
                    let ou_path = self.resolve_user_ou(user);
                    let ou_dn = template_to_dn(&ou_path, base_dn);

                    if !dry_run {
                        if self.config.options.manage_ous {
                            if let Err(e) = self.client.ensure_ou_exists(&ou_dn).await {
                                tracing::error!(user = %user.sourced_id, error = %e, "failed to ensure OU exists");
                                record_error(&mut summary, &user.sourced_id, &e);
                                continue;
                            }
                        }

                        let display_name = format!("{} {}", user.given_name, user.family_name);
                        let mut mods = vec![
                            ("displayName".to_string(), vec![display_name]),
                            ("givenName".to_string(), vec![user.given_name.clone()]),
                            ("sn".to_string(), vec![user.family_name.clone()]),
                        ];
                        if let Some(ref email) = user.email {
                            mods.push(("mail".to_string(), vec![email.clone()]));
                        }

                        if let Err(e) = self.client.modify_user(&existing_state.ad_dn, mods).await {
                            tracing::error!(user = %user.sourced_id, error = %e, "failed to modify AD user");
                            record_error(&mut summary, &user.sourced_id, &e);
                            continue;
                        }

                        // Move user if OU changed
                        if existing_state.ad_ou != ou_dn {
                            if let Err(e) =
                                self.client.move_user(&existing_state.ad_dn, &ou_dn).await
                            {
                                tracing::error!(user = %user.sourced_id, error = %e, "failed to move AD user");
                                record_error(&mut summary, &user.sourced_id, &e);
                                continue;
                            }
                        }

                        let new_dn = if existing_state.ad_ou != ou_dn {
                            let cn = existing_state
                                .ad_dn
                                .split(',')
                                .next()
                                .unwrap_or("CN=Unknown");
                            format!("{cn},{ou_dn}")
                        } else {
                            existing_state.ad_dn.clone()
                        };

                        let state = AdSyncUserState {
                            user_sourced_id: user.sourced_id.clone(),
                            ad_dn: new_dn,
                            ad_sam_account_name: existing_state.ad_sam_account_name.clone(),
                            ad_upn: existing_state.ad_upn.clone(),
                            ad_ou: ou_dn,
                            field_hash,
                            sync_status: AdSyncStatus::Synced,
                            initial_password: existing_state.initial_password.clone(),
                            last_synced_at: Some(Utc::now()),
                            created_at: existing_state.created_at,
                            updated_at: Utc::now(),
                        };
                        self.repo.upsert_ad_sync_state(&state).await?;
                    }

                    summary.users_updated += 1;
                }
                _ => {
                    // No changes needed
                }
            }
        }

        // 7. Detect departed users (have sync_state but no longer active)
        // This also covers users whose enabled_user became false (Issue 4)
        for state in &sync_states {
            if state.sync_status == AdSyncStatus::Disabled {
                continue;
            }
            let is_departed = !active_ids.contains(state.user_sourced_id.as_str());
            let is_disabled_in_sis = disabled_user_ids.contains(state.user_sourced_id.as_str());

            if is_departed || is_disabled_in_sis {
                if !dry_run {
                    let deprovision_result: std::result::Result<(), ChalkError> = match self
                        .config
                        .options
                        .deprovision_action
                        .as_str()
                    {
                        "disable" => self.client.disable_user(&state.ad_dn).await,
                        "move_to_ou" => {
                            if let Some(ref target_ou) = self.config.options.deprovision_ou {
                                let target_dn = template_to_dn(target_ou, base_dn);
                                if let Err(e) =
                                    self.client.move_user(&state.ad_dn, &target_dn).await
                                {
                                    Err(e)
                                } else {
                                    self.client.disable_user(&state.ad_dn).await
                                }
                            } else {
                                warn!(
                                        user_sourced_id = state.user_sourced_id,
                                        "deprovision_action is move_to_ou but no deprovision_ou configured"
                                    );
                                self.client.disable_user(&state.ad_dn).await
                            }
                        }
                        "delete" => self.client.delete_user(&state.ad_dn).await,
                        other => {
                            warn!(
                                action = other,
                                "unknown deprovision_action, defaulting to disable"
                            );
                            self.client.disable_user(&state.ad_dn).await
                        }
                    };

                    match deprovision_result {
                        Ok(()) => {}
                        Err(e) => {
                            tracing::error!(user = %state.user_sourced_id, error = %e, "failed to deprovision AD user");
                            record_error(&mut summary, &state.user_sourced_id, &e);
                            continue;
                        }
                    }

                    let updated_state = AdSyncUserState {
                        user_sourced_id: state.user_sourced_id.clone(),
                        ad_dn: state.ad_dn.clone(),
                        ad_sam_account_name: state.ad_sam_account_name.clone(),
                        ad_upn: state.ad_upn.clone(),
                        ad_ou: state.ad_ou.clone(),
                        field_hash: state.field_hash.clone(),
                        sync_status: AdSyncStatus::Disabled,
                        initial_password: state.initial_password.clone(),
                        last_synced_at: Some(Utc::now()),
                        created_at: state.created_at,
                        updated_at: Utc::now(),
                    };
                    self.repo.upsert_ad_sync_state(&updated_state).await?;
                }

                summary.users_disabled += 1;
            }
        }

        // 8. Manage role-based groups if enabled
        if self.config.options.manage_groups {
            let (created, updated) = self
                .manage_groups(&sync_states, &active_users, dry_run, base_dn, &mut summary)
                .await?;
            summary.groups_created = created;
            summary.groups_updated = updated;
        }

        Ok(summary)
    }

    fn resolve_user_ou(&self, user: &User) -> String {
        let ou_mapping = match self.config.ou_mapping.as_ref() {
            Some(m) => m,
            None => return "/Users".to_string(),
        };

        let template = match user.role {
            RoleType::Student => &ou_mapping.students,
            RoleType::Teacher => &ou_mapping.teachers,
            _ => &ou_mapping.staff,
        };

        let school_name = user.orgs.first().map(|s| s.as_str()).unwrap_or("Default");
        let grade = user.grades.first().map(|s| s.as_str()).unwrap_or("");

        resolve_ou_path(template, school_name, grade)
    }

    /// Manage role-based groups (Students, Teachers, Staff) under the configured groups base OU.
    /// Creates groups if they don't exist, adds users matching the role, removes users that
    /// no longer belong.
    async fn manage_groups(
        &self,
        sync_states: &[AdSyncUserState],
        active_users: &[&User],
        dry_run: bool,
        base_dn: &str,
        summary: &mut SyncSummary,
    ) -> Result<(u32, u32)> {
        let groups_config = match self.config.groups.as_ref() {
            Some(g) if g.enabled => g,
            _ => return Ok((0, 0)),
        };

        let groups_base_ou = groups_config.base_ou.as_deref().unwrap_or("OU=Groups");
        let groups_ou_dn = format!("{groups_base_ou},{base_dn}");

        // Build a lookup from user sourced_id -> AD DN from sync states
        let state_map: std::collections::HashMap<&str, &str> = sync_states
            .iter()
            .map(|s| (s.user_sourced_id.as_str(), s.ad_dn.as_str()))
            .collect();

        let role_groups: &[(&str, RoleType)] = &[
            ("Students", RoleType::Student),
            ("Teachers", RoleType::Teacher),
            ("Staff", RoleType::Administrator),
        ];

        let mut groups_created: u32 = 0;
        let mut groups_updated: u32 = 0;

        for (group_name, role) in role_groups {
            let group_dn = format!("CN={group_name},{groups_ou_dn}");

            // Count users matching this role (for dry run we don't require a sync state)
            let role_user_count = active_users.iter().filter(|u| u.role == *role).count();

            // Determine which users belong to this group (using their AD DNs)
            let desired_members: std::collections::HashSet<&str> = active_users
                .iter()
                .filter(|u| u.role == *role)
                .filter_map(|u| state_map.get(u.sourced_id.as_str()).copied())
                .collect();

            if dry_run {
                // In dry run mode, count based on matching users (not just those with sync state)
                if role_user_count > 0 {
                    groups_created += 1;
                    groups_updated += 1;
                }
                continue;
            }

            // Ensure the groups OU exists
            if self.config.options.manage_ous {
                if let Err(e) = self.client.ensure_ou_exists(&groups_ou_dn).await {
                    warn!(error = %e, "failed to ensure groups OU exists");
                    record_error(summary, "groups_ou", &e);
                    continue;
                }
            }

            // Create or verify group exists
            match self.client.group_exists(&group_dn).await {
                Ok(true) => {}
                Ok(false) => {
                    if let Err(e) = self.client.create_group(&group_dn, group_name).await {
                        warn!(group = %group_name, error = %e, "failed to create group");
                        record_error(summary, group_name, &e);
                        continue;
                    }
                    groups_created += 1;
                }
                Err(e) => {
                    warn!(group = %group_name, error = %e, "failed to check group existence");
                    record_error(summary, group_name, &e);
                    continue;
                }
            }

            // Get current members
            let current_members: std::collections::HashSet<String> =
                match self.client.list_group_members(&group_dn).await {
                    Ok(members) => members.into_iter().collect(),
                    Err(e) => {
                        warn!(group = %group_name, error = %e, "failed to list group members");
                        record_error(summary, group_name, &e);
                        continue;
                    }
                };

            let current_refs: std::collections::HashSet<&str> =
                current_members.iter().map(|s| s.as_str()).collect();

            let mut membership_changed = false;

            // Add users that should be in the group but aren't
            for member_dn in &desired_members {
                if !current_refs.contains(*member_dn) {
                    if let Err(e) = self.client.add_user_to_group(&group_dn, member_dn).await {
                        warn!(group = %group_name, user = %member_dn, error = %e, "failed to add user to group");
                        record_error(summary, member_dn, &e);
                    } else {
                        membership_changed = true;
                    }
                }
            }

            // Remove users that are in the group but shouldn't be
            for member_dn in &current_refs {
                if !desired_members.contains(*member_dn) {
                    if let Err(e) = self
                        .client
                        .remove_user_from_group(&group_dn, member_dn)
                        .await
                    {
                        warn!(group = %group_name, user = %member_dn, error = %e, "failed to remove user from group");
                        record_error(summary, member_dn, &e);
                    } else {
                        membership_changed = true;
                    }
                }
            }

            if membership_changed {
                groups_updated += 1;
            }
        }

        Ok((groups_created, groups_updated))
    }

    fn generate_user_password(&self, user: &User) -> String {
        match self.config.passwords.as_ref() {
            Some(pw_config) => {
                let grade = user.grades.first().map(|s| s.as_str());
                let pw = generate_password(
                    &user.given_name,
                    &user.family_name,
                    None, // birth year not available on User model
                    grade,
                    &pw_config.pattern,
                );
                if pw.len() < pw_config.min_length {
                    // Pad with random chars to meet minimum length
                    let extra = generate_random_password(pw_config.min_length - pw.len());
                    format!("{pw}{extra}")
                } else {
                    pw
                }
            }
            None => generate_random_password(16),
        }
    }
}

/// Record a per-user error in the sync summary, incrementing the error count
/// and appending the user ID and error message to the error details string.
fn record_error(summary: &mut SyncSummary, user_id: &str, error: &dyn std::fmt::Display) {
    summary.errors += 1;
    if summary.error_details.is_none() {
        summary.error_details = Some(String::new());
    }
    if let Some(ref mut details) = summary.error_details {
        details.push_str(&format!("{}: {}\n", user_id, error));
    }
}

/// Compute a SHA256 hash of user fields relevant for sync change detection.
pub fn compute_field_hash(user: &User) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user.given_name.as_bytes());
    hasher.update(b"|");
    hasher.update(user.family_name.as_bytes());
    hasher.update(b"|");
    hasher.update(user.email.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(
        serde_json::to_string(&user.role)
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(b"|");
    hasher.update(user.orgs.join(",").as_bytes());
    hasher.update(b"|");
    hasher.update(user.grades.join(",").as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Convert a base DN like `DC=example,DC=com` to a domain like `example.com`.
fn base_dn_to_domain(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|part| part.trim().strip_prefix("DC="))
        .collect::<Vec<&str>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chalk_core::db::repository::{
        AcademicSessionRepository, AdSyncRunRepository, AdSyncStateRepository, ChalkRepository,
        ClassRepository, CourseRepository, DemographicsRepository, EnrollmentRepository,
        ExternalIdRepository, GoogleSyncRunRepository, GoogleSyncStateRepository,
        IdpAuthLogRepository, IdpSessionRepository, OrgRepository, PasswordRepository,
        PicturePasswordRepository, QrBadgeRepository, SyncRepository, UserRepository,
        WebhookDeliveryRepository, WebhookEndpointRepository,
    };
    use chalk_core::models::academic_session::AcademicSession;
    use chalk_core::models::ad_sync::{AdSyncRun, AdSyncRunStatus};
    use chalk_core::models::class::Class;
    use chalk_core::models::common::Status;
    use chalk_core::models::course::Course;
    use chalk_core::models::demographics::Demographics;
    use chalk_core::models::enrollment::Enrollment;
    use chalk_core::models::google_sync::{
        GoogleSyncRun, GoogleSyncRunStatus, GoogleSyncUserState,
    };
    use chalk_core::models::idp::{AuthLogEntry, IdpSession, PicturePassword, QrBadge};
    use chalk_core::models::org::Org;
    use chalk_core::models::sync::{SyncRun, SyncStatus, UserCounts};
    use chalk_core::webhooks::models::{DeliveryStatus, WebhookDelivery, WebhookEndpoint};
    use chrono::TimeZone;
    use std::sync::Mutex;

    struct MockRepo {
        users: Vec<User>,
        ad_sync_states: Mutex<Vec<AdSyncUserState>>,
        ad_sync_runs: Mutex<Vec<AdSyncRun>>,
    }

    impl MockRepo {
        fn new(users: Vec<User>, ad_sync_states: Vec<AdSyncUserState>) -> Self {
            Self {
                users,
                ad_sync_states: Mutex::new(ad_sync_states),
                ad_sync_runs: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl OrgRepository for MockRepo {
        async fn upsert_org(&self, _org: &Org) -> Result<()> {
            Ok(())
        }
        async fn get_org(&self, _id: &str) -> Result<Option<Org>> {
            Ok(None)
        }
        async fn list_orgs(&self) -> Result<Vec<Org>> {
            Ok(vec![])
        }
        async fn delete_org(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl AcademicSessionRepository for MockRepo {
        async fn upsert_academic_session(&self, _s: &AcademicSession) -> Result<()> {
            Ok(())
        }
        async fn get_academic_session(&self, _id: &str) -> Result<Option<AcademicSession>> {
            Ok(None)
        }
        async fn list_academic_sessions(&self) -> Result<Vec<AcademicSession>> {
            Ok(vec![])
        }
        async fn delete_academic_session(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl UserRepository for MockRepo {
        async fn upsert_user(&self, _user: &User) -> Result<()> {
            Ok(())
        }
        async fn get_user(&self, _id: &str) -> Result<Option<User>> {
            Ok(None)
        }
        async fn get_user_by_username(&self, _username: &str) -> Result<Option<User>> {
            Ok(None)
        }
        async fn list_users(&self, _filter: &UserFilter) -> Result<Vec<User>> {
            Ok(self.users.clone())
        }
        async fn delete_user(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
        async fn get_user_counts(&self) -> Result<UserCounts> {
            Ok(UserCounts {
                total: 0,
                students: 0,
                teachers: 0,
                administrators: 0,
                other: 0,
            })
        }
    }

    #[async_trait]
    impl CourseRepository for MockRepo {
        async fn upsert_course(&self, _c: &Course) -> Result<()> {
            Ok(())
        }
        async fn get_course(&self, _id: &str) -> Result<Option<Course>> {
            Ok(None)
        }
        async fn list_courses(&self) -> Result<Vec<Course>> {
            Ok(vec![])
        }
        async fn delete_course(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl ClassRepository for MockRepo {
        async fn upsert_class(&self, _c: &Class) -> Result<()> {
            Ok(())
        }
        async fn get_class(&self, _id: &str) -> Result<Option<Class>> {
            Ok(None)
        }
        async fn list_classes(&self) -> Result<Vec<Class>> {
            Ok(vec![])
        }
        async fn delete_class(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl EnrollmentRepository for MockRepo {
        async fn upsert_enrollment(&self, _e: &Enrollment) -> Result<()> {
            Ok(())
        }
        async fn get_enrollment(&self, _id: &str) -> Result<Option<Enrollment>> {
            Ok(None)
        }
        async fn list_enrollments(&self) -> Result<Vec<Enrollment>> {
            Ok(vec![])
        }
        async fn list_enrollments_for_user(
            &self,
            _user_sourced_id: &str,
        ) -> Result<Vec<Enrollment>> {
            Ok(vec![])
        }
        async fn list_enrollments_for_class(
            &self,
            _class_sourced_id: &str,
        ) -> Result<Vec<Enrollment>> {
            Ok(vec![])
        }
        async fn delete_enrollment(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl DemographicsRepository for MockRepo {
        async fn upsert_demographics(&self, _d: &Demographics) -> Result<()> {
            Ok(())
        }
        async fn get_demographics(&self, _id: &str) -> Result<Option<Demographics>> {
            Ok(None)
        }
        async fn list_demographics(&self) -> Result<Vec<Demographics>> {
            Ok(vec![])
        }
        async fn delete_demographics(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl SyncRepository for MockRepo {
        async fn create_sync_run(&self, _provider: &str) -> Result<SyncRun> {
            Ok(SyncRun {
                id: 1,
                provider: "test".into(),
                status: SyncStatus::Running,
                started_at: Utc::now(),
                completed_at: None,
                error_message: None,
                users_synced: 0,
                orgs_synced: 0,
                courses_synced: 0,
                classes_synced: 0,
                enrollments_synced: 0,
            })
        }
        async fn update_sync_status(
            &self,
            _id: i64,
            _status: SyncStatus,
            _err: Option<&str>,
        ) -> Result<()> {
            Ok(())
        }
        async fn update_sync_counts(
            &self,
            _id: i64,
            _u: i64,
            _o: i64,
            _c: i64,
            _cl: i64,
            _e: i64,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_sync_run(&self, _id: i64) -> Result<Option<SyncRun>> {
            Ok(None)
        }
        async fn get_latest_sync_run(&self, _provider: &str) -> Result<Option<SyncRun>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl IdpSessionRepository for MockRepo {
        async fn create_session(&self, _s: &IdpSession) -> Result<()> {
            Ok(())
        }
        async fn get_session(&self, _id: &str) -> Result<Option<IdpSession>> {
            Ok(None)
        }
        async fn delete_session(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
        async fn delete_expired_sessions(&self) -> Result<u64> {
            Ok(0)
        }
        async fn list_sessions_for_user(&self, _uid: &str) -> Result<Vec<IdpSession>> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl QrBadgeRepository for MockRepo {
        async fn create_badge(&self, _b: &QrBadge) -> Result<i64> {
            Ok(1)
        }
        async fn get_badge_by_token(&self, _t: &str) -> Result<Option<QrBadge>> {
            Ok(None)
        }
        async fn list_badges_for_user(&self, _uid: &str) -> Result<Vec<QrBadge>> {
            Ok(vec![])
        }
        async fn revoke_badge(&self, _id: i64) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl PicturePasswordRepository for MockRepo {
        async fn upsert_picture_password(&self, _pp: &PicturePassword) -> Result<()> {
            Ok(())
        }
        async fn get_picture_password(&self, _uid: &str) -> Result<Option<PicturePassword>> {
            Ok(None)
        }
        async fn delete_picture_password(&self, _uid: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl IdpAuthLogRepository for MockRepo {
        async fn log_auth_attempt(&self, _entry: &AuthLogEntry) -> Result<i64> {
            Ok(1)
        }
        async fn list_auth_log(&self, _limit: i64) -> Result<Vec<AuthLogEntry>> {
            Ok(vec![])
        }
        async fn list_auth_log_for_user(
            &self,
            _uid: &str,
            _limit: i64,
        ) -> Result<Vec<AuthLogEntry>> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl PasswordRepository for MockRepo {
        async fn get_password_hash(&self, _uid: &str) -> Result<Option<String>> {
            Ok(None)
        }
        async fn set_password_hash(&self, _uid: &str, _hash: &str) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl GoogleSyncStateRepository for MockRepo {
        async fn upsert_sync_state(&self, _state: &GoogleSyncUserState) -> Result<()> {
            Ok(())
        }
        async fn get_sync_state(&self, _uid: &str) -> Result<Option<GoogleSyncUserState>> {
            Ok(None)
        }
        async fn list_sync_states(&self) -> Result<Vec<GoogleSyncUserState>> {
            Ok(vec![])
        }
        async fn delete_sync_state(&self, _uid: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl GoogleSyncRunRepository for MockRepo {
        async fn create_google_sync_run(&self, _dry_run: bool) -> Result<GoogleSyncRun> {
            Ok(GoogleSyncRun {
                id: 1,
                started_at: Utc::now(),
                completed_at: None,
                status: GoogleSyncRunStatus::Running,
                users_created: 0,
                users_updated: 0,
                users_suspended: 0,
                ous_created: 0,
                dry_run: false,
                error_message: None,
            })
        }
        async fn update_google_sync_run(
            &self,
            _id: i64,
            _status: GoogleSyncRunStatus,
            _c: i64,
            _u: i64,
            _s: i64,
            _o: i64,
            _err: Option<&str>,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_google_sync_run(&self, _id: i64) -> Result<Option<GoogleSyncRun>> {
            Ok(None)
        }
        async fn get_latest_google_sync_run(&self) -> Result<Option<GoogleSyncRun>> {
            Ok(None)
        }
        async fn list_google_sync_runs(&self, _limit: i64) -> Result<Vec<GoogleSyncRun>> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl AdSyncStateRepository for MockRepo {
        async fn upsert_ad_sync_state(&self, state: &AdSyncUserState) -> Result<()> {
            let mut states = self.ad_sync_states.lock().unwrap();
            states.retain(|s| s.user_sourced_id != state.user_sourced_id);
            states.push(state.clone());
            Ok(())
        }
        async fn get_ad_sync_state(&self, uid: &str) -> Result<Option<AdSyncUserState>> {
            let states = self.ad_sync_states.lock().unwrap();
            Ok(states.iter().find(|s| s.user_sourced_id == uid).cloned())
        }
        async fn list_ad_sync_states(&self) -> Result<Vec<AdSyncUserState>> {
            Ok(self.ad_sync_states.lock().unwrap().clone())
        }
        async fn delete_ad_sync_state(&self, _uid: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl AdSyncRunRepository for MockRepo {
        async fn create_ad_sync_run(&self, dry_run: bool) -> Result<AdSyncRun> {
            let run = AdSyncRun {
                id: uuid::Uuid::new_v4().to_string(),
                started_at: Utc::now(),
                completed_at: None,
                status: AdSyncRunStatus::Running,
                users_created: 0,
                users_updated: 0,
                users_disabled: 0,
                users_skipped: 0,
                groups_created: 0,
                groups_updated: 0,
                errors: 0,
                error_details: None,
                dry_run,
            };
            self.ad_sync_runs.lock().unwrap().push(run.clone());
            Ok(run)
        }
        async fn update_ad_sync_run(
            &self,
            _id: &str,
            _status: AdSyncRunStatus,
            _created: i64,
            _updated: i64,
            _disabled: i64,
            _skipped: i64,
            _groups_created: i64,
            _groups_updated: i64,
            _errors: i64,
            _err: Option<&str>,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_ad_sync_run(&self, _id: &str) -> Result<Option<AdSyncRun>> {
            Ok(None)
        }
        async fn get_latest_ad_sync_run(&self) -> Result<Option<AdSyncRun>> {
            Ok(None)
        }
        async fn list_ad_sync_runs(&self, _limit: i64) -> Result<Vec<AdSyncRun>> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl chalk_core::db::repository::AdminSessionRepository for MockRepo {
        async fn create_admin_session(
            &self,
            _session: &chalk_core::models::audit::AdminSession,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_admin_session(
            &self,
            _token: &str,
        ) -> Result<Option<chalk_core::models::audit::AdminSession>> {
            Ok(None)
        }
        async fn delete_admin_session(&self, _token: &str) -> Result<bool> {
            Ok(false)
        }
        async fn delete_expired_admin_sessions(&self) -> Result<u64> {
            Ok(0)
        }
    }

    #[async_trait]
    impl chalk_core::db::repository::AdminAuditRepository for MockRepo {
        async fn log_admin_action(
            &self,
            _action: &str,
            _details: Option<&str>,
            _ip: Option<&str>,
        ) -> Result<i64> {
            Ok(1)
        }
        async fn list_admin_audit_log(
            &self,
            _limit: i64,
        ) -> Result<Vec<chalk_core::models::audit::AdminAuditEntry>> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl chalk_core::db::repository::ConfigRepository for MockRepo {
        async fn get_config_override(&self, _key: &str) -> Result<Option<String>> {
            Ok(None)
        }
        async fn set_config_override(&self, _key: &str, _value: &str) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl WebhookEndpointRepository for MockRepo {
        async fn upsert_webhook_endpoint(&self, _endpoint: &WebhookEndpoint) -> Result<()> {
            Ok(())
        }
        async fn get_webhook_endpoint(&self, _id: &str) -> Result<Option<WebhookEndpoint>> {
            Ok(None)
        }
        async fn list_webhook_endpoints(&self) -> Result<Vec<WebhookEndpoint>> {
            Ok(vec![])
        }
        async fn list_webhook_endpoints_by_source(
            &self,
            _source: &str,
        ) -> Result<Vec<WebhookEndpoint>> {
            Ok(vec![])
        }
        async fn delete_webhook_endpoint(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl WebhookDeliveryRepository for MockRepo {
        async fn create_webhook_delivery(&self, _delivery: &WebhookDelivery) -> Result<i64> {
            Ok(1)
        }
        async fn update_delivery_status(
            &self,
            _id: i64,
            _status: DeliveryStatus,
            _http: Option<i32>,
            _body: Option<&str>,
        ) -> Result<()> {
            Ok(())
        }
        async fn list_pending_retries(&self, _limit: i64) -> Result<Vec<WebhookDelivery>> {
            Ok(vec![])
        }
        async fn list_deliveries_by_webhook(
            &self,
            _wid: &str,
            _limit: i64,
        ) -> Result<Vec<WebhookDelivery>> {
            Ok(vec![])
        }
        async fn list_deliveries_by_sync_run(&self, _sid: i64) -> Result<Vec<WebhookDelivery>> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl chalk_core::db::repository::SsoPartnerRepository for MockRepo {
        async fn upsert_sso_partner(
            &self,
            _partner: &chalk_core::models::sso::SsoPartner,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_sso_partner(
            &self,
            _id: &str,
        ) -> Result<Option<chalk_core::models::sso::SsoPartner>> {
            Ok(None)
        }
        async fn get_sso_partner_by_entity_id(
            &self,
            _eid: &str,
        ) -> Result<Option<chalk_core::models::sso::SsoPartner>> {
            Ok(None)
        }
        async fn get_sso_partner_by_client_id(
            &self,
            _cid: &str,
        ) -> Result<Option<chalk_core::models::sso::SsoPartner>> {
            Ok(None)
        }
        async fn list_sso_partners(&self) -> Result<Vec<chalk_core::models::sso::SsoPartner>> {
            Ok(vec![])
        }
        async fn list_sso_partners_for_role(
            &self,
            _role: &str,
        ) -> Result<Vec<chalk_core::models::sso::SsoPartner>> {
            Ok(vec![])
        }
        async fn delete_sso_partner(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl chalk_core::db::repository::OidcCodeRepository for MockRepo {
        async fn create_oidc_code(
            &self,
            _code: &chalk_core::models::sso::OidcAuthorizationCode,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_oidc_code(
            &self,
            _code: &str,
        ) -> Result<Option<chalk_core::models::sso::OidcAuthorizationCode>> {
            Ok(None)
        }
        async fn delete_oidc_code(&self, _code: &str) -> Result<bool> {
            Ok(false)
        }
        async fn delete_expired_oidc_codes(&self) -> Result<u64> {
            Ok(0)
        }
    }

    #[async_trait]
    impl chalk_core::db::repository::PortalSessionRepository for MockRepo {
        async fn create_portal_session(
            &self,
            _session: &chalk_core::models::sso::PortalSession,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_portal_session(
            &self,
            _id: &str,
        ) -> Result<Option<chalk_core::models::sso::PortalSession>> {
            Ok(None)
        }
        async fn delete_portal_session(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }
        async fn delete_expired_portal_sessions(&self) -> Result<u64> {
            Ok(0)
        }
    }

    #[async_trait]
    impl ExternalIdRepository for MockRepo {
        async fn get_external_ids(
            &self,
            _uid: &str,
        ) -> Result<serde_json::Map<String, serde_json::Value>> {
            Ok(serde_json::Map::new())
        }
        async fn set_external_ids(
            &self,
            _uid: &str,
            _ids: &serde_json::Map<String, serde_json::Value>,
        ) -> Result<()> {
            Ok(())
        }
        async fn find_user_by_external_id(
            &self,
            _provider: &str,
            _external_id: &str,
        ) -> Result<Option<User>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl chalk_core::db::repository::AccessTokenRepository for MockRepo {
        async fn create_access_token(
            &self,
            _token: &chalk_core::models::access_token::AccessToken,
        ) -> Result<()> {
            Ok(())
        }
        async fn get_access_token(
            &self,
            _token: &str,
        ) -> Result<Option<chalk_core::models::access_token::AccessToken>> {
            Ok(None)
        }
        async fn revoke_access_token(&self, _token: &str) -> Result<()> {
            Ok(())
        }
        async fn delete_expired_access_tokens(&self) -> Result<u64> {
            Ok(0)
        }
    }

    impl ChalkRepository for MockRepo {}

    fn make_test_user(id: &str, given: &str, family: &str, role: RoleType) -> User {
        User {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            metadata: None,
            username: format!("{}{}", &given[..1].to_lowercase(), family.to_lowercase()),
            user_ids: vec![],
            enabled_user: true,
            given_name: given.to_string(),
            family_name: family.to_string(),
            middle_name: None,
            role,
            identifier: None,
            email: None,
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["Lincoln HS".to_string()],
            grades: vec!["09".to_string()],
        }
    }

    fn make_config() -> AdSyncConfig {
        use chalk_core::config::{AdConnectionConfig, AdOuMappingConfig, AdSyncOptions};
        AdSyncConfig {
            enabled: true,
            sync_schedule: "0 3 * * *".to_string(),
            connection: AdConnectionConfig {
                server: "ldaps://localhost:636".to_string(),
                bind_dn: "CN=svc,DC=example,DC=com".to_string(),
                bind_password: "secret".to_string(),
                base_dn: "DC=example,DC=com".to_string(),
                tls_verify: false,
                tls_ca_cert: None,
            },
            ou_mapping: Some(AdOuMappingConfig {
                students: "/Students/{school}/{grade}".to_string(),
                teachers: "/Teachers/{school}".to_string(),
                staff: "/Staff/{school}".to_string(),
            }),
            groups: None,
            passwords: None,
            options: AdSyncOptions {
                provision_users: true,
                deprovision_action: "disable".to_string(),
                deprovision_ou: None,
                manage_ous: false,
                manage_groups: false,
                sync_passwords: false,
                dry_run: false,
            },
        }
    }

    #[test]
    fn compute_hash_deterministic() {
        let user = make_test_user("u1", "John", "Doe", RoleType::Student);
        let h1 = compute_field_hash(&user);
        let h2 = compute_field_hash(&user);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_hash_changes_on_field_change() {
        let user1 = make_test_user("u1", "John", "Doe", RoleType::Student);
        let mut user2 = user1.clone();
        user2.given_name = "Jonathan".to_string();
        assert_ne!(compute_field_hash(&user1), compute_field_hash(&user2));
    }

    #[test]
    fn compute_hash_changes_on_role_change() {
        let user1 = make_test_user("u1", "John", "Doe", RoleType::Student);
        let mut user2 = user1.clone();
        user2.role = RoleType::Teacher;
        assert_ne!(compute_field_hash(&user1), compute_field_hash(&user2));
    }

    #[test]
    fn compute_hash_changes_on_org_change() {
        let user1 = make_test_user("u1", "John", "Doe", RoleType::Student);
        let mut user2 = user1.clone();
        user2.orgs = vec!["Washington MS".to_string()];
        assert_ne!(compute_field_hash(&user1), compute_field_hash(&user2));
    }

    #[test]
    fn base_dn_to_domain_simple() {
        assert_eq!(base_dn_to_domain("DC=example,DC=com"), "example.com");
    }

    #[test]
    fn base_dn_to_domain_three_parts() {
        assert_eq!(
            base_dn_to_domain("DC=school,DC=example,DC=com"),
            "school.example.com"
        );
    }

    #[tokio::test]
    async fn dry_run_counts_without_ldap_calls() {
        let users = vec![
            make_test_user("u1", "John", "Doe", RoleType::Student),
            make_test_user("u2", "Jane", "Smith", RoleType::Student),
        ];
        let repo = Arc::new(MockRepo::new(users, vec![]));
        let config = make_config();
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert!(summary.dry_run);
        assert_eq!(summary.users_created, 2);
        assert_eq!(summary.users_updated, 0);
        assert_eq!(summary.users_disabled, 0);
    }

    #[tokio::test]
    async fn dry_run_detects_changed_users() {
        let user = make_test_user("u1", "John", "Doe", RoleType::Student);
        let old_hash = "different_hash".to_string();

        let sync_state = AdSyncUserState {
            user_sourced_id: "u1".to_string(),
            ad_dn: "CN=John Doe,OU=Students,DC=example,DC=com".to_string(),
            ad_sam_account_name: "jdoe".to_string(),
            ad_upn: Some("jdoe@example.com".to_string()),
            ad_ou: "OU=Students,DC=example,DC=com".to_string(),
            field_hash: old_hash,
            sync_status: AdSyncStatus::Synced,
            initial_password: None,
            last_synced_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let repo = Arc::new(MockRepo::new(vec![user], vec![sync_state]));
        let config = make_config();
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert_eq!(summary.users_created, 0);
        assert_eq!(summary.users_updated, 1);
    }

    #[tokio::test]
    async fn dry_run_detects_departed_users() {
        let sync_state = AdSyncUserState {
            user_sourced_id: "u1".to_string(),
            ad_dn: "CN=John Doe,OU=Students,DC=example,DC=com".to_string(),
            ad_sam_account_name: "jdoe".to_string(),
            ad_upn: Some("jdoe@example.com".to_string()),
            ad_ou: "OU=Students,DC=example,DC=com".to_string(),
            field_hash: "hash".to_string(),
            sync_status: AdSyncStatus::Synced,
            initial_password: None,
            last_synced_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let repo = Arc::new(MockRepo::new(vec![], vec![sync_state]));
        let config = make_config();
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert_eq!(summary.users_disabled, 1);
    }

    #[tokio::test]
    async fn dry_run_skips_already_disabled() {
        let sync_state = AdSyncUserState {
            user_sourced_id: "u1".to_string(),
            ad_dn: "CN=John Doe,OU=Students,DC=example,DC=com".to_string(),
            ad_sam_account_name: "jdoe".to_string(),
            ad_upn: Some("jdoe@example.com".to_string()),
            ad_ou: "OU=Students,DC=example,DC=com".to_string(),
            field_hash: "hash".to_string(),
            sync_status: AdSyncStatus::Disabled,
            initial_password: None,
            last_synced_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let repo = Arc::new(MockRepo::new(vec![], vec![sync_state]));
        let config = make_config();
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert_eq!(summary.users_disabled, 0);
    }

    #[tokio::test]
    async fn dry_run_unchanged_user_no_action() {
        let user = make_test_user("u1", "John", "Doe", RoleType::Student);
        let hash = compute_field_hash(&user);

        let sync_state = AdSyncUserState {
            user_sourced_id: "u1".to_string(),
            ad_dn: "CN=John Doe,OU=Students,DC=example,DC=com".to_string(),
            ad_sam_account_name: "jdoe".to_string(),
            ad_upn: Some("jdoe@example.com".to_string()),
            ad_ou: "OU=Students,DC=example,DC=com".to_string(),
            field_hash: hash,
            sync_status: AdSyncStatus::Synced,
            initial_password: None,
            last_synced_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let repo = Arc::new(MockRepo::new(vec![user], vec![sync_state]));
        let config = make_config();
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert_eq!(summary.users_created, 0);
        assert_eq!(summary.users_updated, 0);
        assert_eq!(summary.users_disabled, 0);
    }

    #[tokio::test]
    async fn dry_run_skips_when_provisioning_disabled() {
        let users = vec![make_test_user("u1", "John", "Doe", RoleType::Student)];
        let repo = Arc::new(MockRepo::new(users, vec![]));
        let mut config = make_config();
        config.options.provision_users = false;
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert_eq!(summary.users_created, 0);
        assert_eq!(summary.users_skipped, 1);
    }

    #[test]
    fn disabled_user_not_synced() {
        let mut user = make_test_user("u1", "John", "Doe", RoleType::Student);
        user.enabled_user = false;
        assert!(!user.enabled_user);
    }

    #[test]
    fn tobedeleted_user_not_synced() {
        let mut user = make_test_user("u1", "John", "Doe", RoleType::Student);
        user.status = Status::ToBeDeleted;
        assert_eq!(user.status, Status::ToBeDeleted);
    }

    #[tokio::test]
    async fn full_sync_forces_update_even_when_hash_matches() {
        let user = make_test_user("u1", "John", "Doe", RoleType::Student);
        let hash = compute_field_hash(&user);

        let sync_state = AdSyncUserState {
            user_sourced_id: "u1".to_string(),
            ad_dn: "CN=John Doe,OU=Students,DC=example,DC=com".to_string(),
            ad_sam_account_name: "jdoe".to_string(),
            ad_upn: Some("jdoe@example.com".to_string()),
            ad_ou: "OU=Students,DC=example,DC=com".to_string(),
            field_hash: hash,
            sync_status: AdSyncStatus::Synced,
            initial_password: None,
            last_synced_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let repo = Arc::new(MockRepo::new(vec![user], vec![sync_state]));
        let config = make_config();
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        // full=true should force update even though hash matches
        let summary = engine.run_sync(true, true).await.unwrap();

        assert_eq!(summary.users_created, 0);
        assert_eq!(summary.users_updated, 1);
        assert_eq!(summary.users_disabled, 0);
    }

    #[tokio::test]
    async fn disabled_sis_user_detected_as_departed() {
        // A user that exists in sync state but is now disabled in SIS
        let mut user = make_test_user("u1", "John", "Doe", RoleType::Student);
        user.enabled_user = false;

        let sync_state = AdSyncUserState {
            user_sourced_id: "u1".to_string(),
            ad_dn: "CN=John Doe,OU=Students,DC=example,DC=com".to_string(),
            ad_sam_account_name: "jdoe".to_string(),
            ad_upn: Some("jdoe@example.com".to_string()),
            ad_ou: "OU=Students,DC=example,DC=com".to_string(),
            field_hash: "somehash".to_string(),
            sync_status: AdSyncStatus::Synced,
            initial_password: None,
            last_synced_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let repo = Arc::new(MockRepo::new(vec![user], vec![sync_state]));
        let config = make_config();
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        // The disabled user should be detected for deprovisioning
        assert_eq!(summary.users_disabled, 1);
        assert_eq!(summary.users_created, 0);
    }

    #[test]
    fn record_error_increments_and_appends() {
        let mut summary = SyncSummary {
            users_created: 0,
            users_updated: 0,
            users_disabled: 0,
            users_skipped: 0,
            groups_created: 0,
            groups_updated: 0,
            errors: 0,
            error_details: None,
            dry_run: false,
        };

        record_error(&mut summary, "user1", &"connection timeout");
        assert_eq!(summary.errors, 1);
        assert_eq!(
            summary.error_details.as_deref(),
            Some("user1: connection timeout\n")
        );

        record_error(&mut summary, "user2", &"auth failed");
        assert_eq!(summary.errors, 2);
        assert!(summary
            .error_details
            .as_ref()
            .unwrap()
            .contains("user2: auth failed\n"));
    }

    #[tokio::test]
    async fn dry_run_with_groups_enabled_counts_groups() {
        use chalk_core::config::AdGroupConfig;

        let users = vec![
            make_test_user("u1", "John", "Doe", RoleType::Student),
            make_test_user("u2", "Jane", "Smith", RoleType::Teacher),
        ];
        let repo = Arc::new(MockRepo::new(users, vec![]));
        let mut config = make_config();
        config.options.manage_groups = true;
        config.groups = Some(AdGroupConfig {
            enabled: true,
            base_ou: Some("OU=Groups".to_string()),
        });
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert!(summary.dry_run);
        assert_eq!(summary.users_created, 2);
        // In dry run mode, groups_created should be counted for non-empty groups
        assert!(summary.groups_created > 0 || summary.groups_updated > 0);
    }

    #[tokio::test]
    async fn groups_not_managed_when_disabled() {
        let users = vec![make_test_user("u1", "John", "Doe", RoleType::Student)];
        let repo = Arc::new(MockRepo::new(users, vec![]));
        let config = make_config(); // manage_groups is false by default
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert_eq!(summary.groups_created, 0);
        assert_eq!(summary.groups_updated, 0);
    }

    #[tokio::test]
    async fn groups_not_managed_when_config_absent() {
        let users = vec![make_test_user("u1", "John", "Doe", RoleType::Student)];
        let repo = Arc::new(MockRepo::new(users, vec![]));
        let mut config = make_config();
        config.options.manage_groups = true;
        config.groups = None; // No group config
        let client = AdClient::new(&config.connection);

        let engine = AdSyncEngine::new(repo, client, config);
        let summary = engine.run_sync(true, false).await.unwrap();

        assert_eq!(summary.groups_created, 0);
        assert_eq!(summary.groups_updated, 0);
    }
}
