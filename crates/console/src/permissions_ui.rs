//! Settings surfaces for GP-2: custom permission sets, and per-account
//! access (which set, which schools).
//!
//! Both live under `consoleusers.manage` in the authz table — the person who
//! can create accounts is the person who can decide what they may do.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::permission::{ConsoleAuthz, Permission, PermissionSet};
use chrono::Utc;
use serde::Deserialize;

use crate::AppState;

pub const PERMISSION_SETS_PATH: &str = "/settings/permission-sets";

// ---------------------------------------------------------------------------
// Permission sets: list + create + delete
// ---------------------------------------------------------------------------

pub struct SetRow {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub count: usize,
}

pub struct PermissionOption {
    pub key: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub is_read: bool,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/permission_sets.html")]
pub struct PermissionSetsTemplate {
    pub nav: crate::nav::Nav,
    pub rows: Vec<SetRow>,
    pub options: Vec<PermissionOption>,
    pub notice: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NoticeQuery {
    pub notice: String,
}

fn notice_message(notice: &str) -> String {
    match notice {
        "created" => "Permission set saved.".into(),
        "deleted" => "Permission set deleted.".into(),
        "in_use" => "That set is assigned to an account, so it cannot be deleted.".into(),
        "bad_input" => "Give the set a name and at least one permission.".into(),
        "failed" => "That did not work — try again.".into(),
        _ => String::new(),
    }
}

/// `GET /settings/permission-sets`
pub async fn sets_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Query(q): Query<NoticeQuery>,
) -> Response {
    let Some(store) = state.permission_sets.clone() else {
        return not_configured();
    };
    let rows = store
        .list_permission_sets()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| SetRow {
            id: s.id.clone(),
            name: s.name.clone(),
            summary: s
                .permissions
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            count: s.permissions.len(),
        })
        .collect();
    PermissionSetsTemplate {
        nav: crate::nav::Nav::new(&state.config, "console_users"),
        rows,
        options: Permission::ALL
            .iter()
            .map(|p| PermissionOption {
                key: p.as_str(),
                label: p.label(),
                description: p.description(),
                is_read: p.is_read(),
            })
            .collect(),
        notice: notice_message(&q.notice),
        csrf_token: csrf.0,
    }
    .into_response()
}

/// The set-builder form, parsed by hand like `unmatched::BulkForm`: axum's
/// `Form` is `serde_urlencoded`, which cannot put repeated keys in a `Vec`,
/// and a checkbox grid is exactly repeated keys.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NewSetForm {
    pub name: String,
    pub perms: Vec<String>,
}

impl NewSetForm {
    pub fn parse(body: &str) -> Self {
        let mut form = NewSetForm::default();
        for pair in body.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let decoded = urlencoding::decode(&value.replace('+', " "))
                .map(|v| v.into_owned())
                .unwrap_or_default();
            match key {
                "name" => form.name = decoded,
                "perm" if !decoded.is_empty() => form.perms.push(decoded),
                _ => {}
            }
        }
        form
    }
}

/// `POST /settings/permission-sets`
pub async fn create_set(State(state): State<Arc<AppState>>, body: String) -> Response {
    let form = NewSetForm::parse(&body);
    let Some(store) = state.permission_sets.clone() else {
        return back("failed");
    };
    let name = form.name.trim();
    let mut permissions = Vec::new();
    for key in &form.perms {
        // Unknown keys are refused outright rather than skipped: a typo that
        // silently dropped a permission would create a narrower set than the
        // admin believes they made.
        match Permission::parse(key.trim()) {
            Ok(p) => {
                if !permissions.contains(&p) {
                    permissions.push(p);
                }
            }
            Err(_) => return back("bad_input"),
        }
    }
    if name.is_empty() || permissions.is_empty() {
        return back("bad_input");
    }
    let now = Utc::now();
    let set = PermissionSet {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        permissions,
        created_at: now,
        updated_at: now,
    };
    match store.create_permission_set(&set).await {
        Ok(()) => back("created"),
        Err(e) => {
            tracing::error!("create_permission_set failed: {e}");
            back("failed")
        }
    }
}

/// `POST /settings/permission-sets/{id}/delete`
pub async fn delete_set(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(store) = state.permission_sets.clone() else {
        return back("failed");
    };
    match store.delete_permission_set(&id).await {
        Ok(true) => back("deleted"),
        Ok(false) => back("in_use"),
        Err(e) => {
            tracing::error!("delete_permission_set failed: {e}");
            back("failed")
        }
    }
}

// ---------------------------------------------------------------------------
// Per-account access: set assignment + site grants
// ---------------------------------------------------------------------------

pub struct SetChoice {
    pub id: String,
    pub name: String,
    pub selected: bool,
}

pub struct SchoolChoice {
    pub sourced_id: String,
    pub name: String,
    pub granted: bool,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/console_user_access.html")]
pub struct AccessTemplate {
    pub nav: crate::nav::Nav,
    pub user_id: String,
    pub user_label: String,
    pub role: String,
    pub sets: Vec<SetChoice>,
    pub role_selected: bool,
    pub schools: Vec<SchoolChoice>,
    pub district_wide: bool,
    pub include_unscoped: bool,
    pub csrf_token: String,
}

/// `GET /settings/console-users/{id}/access`
pub async fn access_page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Path(id): Path<String>,
) -> Response {
    let (Some(users), Some(store)) = (state.console_users.clone(), state.permission_sets.clone())
    else {
        return not_configured();
    };
    let Ok(Some(user)) = users.get_console_user(&id).await else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Html("<h1>No such account.</h1>".to_string()),
        )
            .into_response();
    };
    let authz = store
        .get_console_authz(&id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let sets = store
        .list_permission_sets()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| SetChoice {
            selected: authz.permission_set_id.as_deref() == Some(s.id.as_str()),
            id: s.id,
            name: s.name,
        })
        .collect::<Vec<_>>();
    let schools = state
        .repo
        .list_orgs()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|o| o.org_type == chalk_core::models::common::OrgType::School)
        .map(|o| SchoolChoice {
            granted: authz.sites.contains(&o.sourced_id),
            sourced_id: o.sourced_id,
            name: o.name,
        })
        .collect();
    AccessTemplate {
        nav: crate::nav::Nav::new(&state.config, "console_users"),
        user_id: user.id.clone(),
        user_label: format!("{} ({})", user.display_name, user.email),
        role: user.role.as_str().to_string(),
        role_selected: authz.permission_set_id.is_none(),
        sets,
        district_wide: authz.sites.is_empty(),
        include_unscoped: authz.include_unscoped,
        schools,
        csrf_token: csrf.0,
    }
    .into_response()
}

/// Hand-parsed for the same repeated-key reason as [`NewSetForm`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AccessForm {
    /// `"role"` for the role preset, otherwise a permission-set id.
    pub permissions: String,
    /// Checked school org ids. Empty means district-wide.
    pub sites: Vec<String>,
    pub include_unscoped: bool,
}

impl AccessForm {
    pub fn parse(body: &str) -> Self {
        let mut form = AccessForm::default();
        for pair in body.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let decoded = urlencoding::decode(&value.replace('+', " "))
                .map(|v| v.into_owned())
                .unwrap_or_default();
            match key {
                "permissions" => form.permissions = decoded,
                "site" if !decoded.is_empty() => form.sites.push(decoded),
                "include_unscoped" => form.include_unscoped = true,
                _ => {}
            }
        }
        form
    }
}

/// `POST /settings/console-users/{id}/access`
pub async fn access_submit(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let form = AccessForm::parse(&body);
    let Some(store) = state.permission_sets.clone() else {
        return Redirect::to("/settings/console-users?err=Access%20is%20not%20available%20here.")
            .into_response();
    };
    let err = |m: &str| {
        Redirect::to(&format!(
            "/settings/console-users?err={}",
            urlencoding::encode(m)
        ))
        .into_response()
    };
    let permission_set_id = match form.permissions.trim() {
        "role" | "" => None,
        set_id => match store.get_permission_set(set_id).await {
            // The id must name a real set: assigning a ghost would fall back
            // to the role while the page claims otherwise.
            Ok(Some(s)) => Some(s.id),
            _ => return err("That permission set no longer exists."),
        },
    };
    let authz = ConsoleAuthz {
        permission_set_id,
        include_unscoped: form.include_unscoped,
        sites: {
            let mut sites: Vec<String> = form
                .sites
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            sites.sort();
            sites.dedup();
            sites
        },
    };
    match store.set_console_authz(&id, &authz).await {
        Ok(true) => {
            let _ = state
                .repo
                .log_admin_action("console_user_access_changed", Some(&id), None)
                .await;
            Redirect::to("/settings/console-users?ok=Access%20updated.").into_response()
        }
        Ok(false) => err("No such account."),
        Err(e) => {
            tracing::error!("set_console_authz failed: {e}");
            err("Could not update access.")
        }
    }
}

fn back(notice: &str) -> Response {
    Redirect::to(&format!("{PERMISSION_SETS_PATH}?notice={notice}")).into_response()
}

fn not_configured() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Permission sets are not available here.</h1>".to_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
