//! Routing rules — the settings page that manages auto-assignment (WS-11).
//!
//! The rules themselves are matched inside `TicketService`
//! (`chalk_core::models::routing::best_match`), so this page only creates and
//! deletes rows. Editing is deliberately absent: a rule is a one-line fact, and
//! delete-and-recreate is clearer than an edit form that invites drift.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::routing::RoutingRule;
use serde::Deserialize;

use crate::AppState;

pub const ROUTING_PATH: &str = "/settings/routing-rules";

pub struct RuleView {
    pub id: String,
    pub category: String,
    pub school: String,
    pub technician: String,
}

struct Flash {
    kind: String,
    message: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "settings/routing_rules.html")]
struct RoutingTemplate {
    nav: crate::nav::Nav,
    rules: Vec<RuleView>,
    /// `(id, name)` of active technicians for the assignee select.
    technicians: Vec<(String, String)>,
    /// `(sourced_id, name)` of schools for the school select.
    schools: Vec<(String, String)>,
    flash: Option<Flash>,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct FlashQuery {
    #[serde(default)]
    ok: Option<String>,
    #[serde(default)]
    err: Option<String>,
}

fn not_available() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html("<h1>Routing rules are not available on this build.</h1>".to_string()),
    )
        .into_response()
}

/// `GET /settings/routing-rules`
pub async fn page(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Query(flash_q): Query<FlashQuery>,
) -> Response {
    let (Some(repo), Some(users)) = (state.routing_rules.clone(), state.console_users.clone())
    else {
        return not_available();
    };

    let techs = users.list_console_users().await.unwrap_or_default();
    let tech_name = |id: &str| {
        techs
            .iter()
            .find(|u| u.id == id)
            .map(|u| u.display_name.clone())
            // Named rather than blanked: a row nobody can chase is worse.
            .unwrap_or_else(|| id.to_string())
    };
    let schools = school_names(&state).await;
    let school_name = |id: &str| {
        schools
            .iter()
            .find(|(sid, _)| sid == id)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| id.to_string())
    };

    let rules = repo
        .list_routing_rules()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| RuleView {
            id: r.id,
            category: r.category.unwrap_or_else(|| "Any category".to_string()),
            school: r
                .school_org_sourced_id
                .as_deref()
                .map(school_name)
                .unwrap_or_else(|| "Any school".to_string()),
            technician: tech_name(&r.assignee_console_user_id),
        })
        .collect();

    let flash = flash_q
        .ok
        .map(|m| Flash {
            kind: "success".to_string(),
            message: m,
        })
        .or_else(|| {
            flash_q.err.map(|m| Flash {
                kind: "warning".to_string(),
                message: m,
            })
        });

    RoutingTemplate {
        nav: crate::nav::Nav::new(&state.config, "routing_rules"),
        rules,
        technicians: techs
            .iter()
            .filter(|u| u.is_active())
            .map(|u| (u.id.clone(), u.display_name.clone()))
            .collect(),
        schools,
        flash,
        csrf_token: csrf.0,
    }
    .into_response()
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct CreateForm {
    category: String,
    school: String,
    technician: String,
}

/// `POST /settings/routing-rules`
pub async fn create(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<CreateForm>,
) -> Response {
    let (Some(repo), Some(users)) = (state.routing_rules.clone(), state.console_users.clone())
    else {
        return not_available();
    };
    let technician = form.technician.trim();
    // The FK would catch an unknown id, but a suspended technician still
    // satisfies it — same rule as manual assignment.
    let is_active = users
        .list_console_users()
        .await
        .unwrap_or_default()
        .iter()
        .any(|u| u.id == technician && u.is_active());
    if !is_active {
        return Redirect::to(&format!("{ROUTING_PATH}?err=Choose+an+active+technician."))
            .into_response();
    }
    let category = form.category.trim();
    let school = form.school.trim();
    if category.is_empty() && school.is_empty() {
        // A rule with no conditions is a catch-all. Legal, but it must be said
        // deliberately — require at least one condition or the explicit word.
        // "any" in the category box is that word.
        return Redirect::to(&format!(
            "{ROUTING_PATH}?err=Give+the+rule+a+category+or+a+school+%28or+type+%22any%22+as+the+category+for+a+catch-all%29."
        ))
        .into_response();
    }
    let rule = RoutingRule {
        id: uuid::Uuid::new_v4().to_string(),
        category: (!category.is_empty() && !category.eq_ignore_ascii_case("any"))
            .then(|| category.to_lowercase()),
        school_org_sourced_id: (!school.is_empty()).then(|| school.to_string()),
        assignee_console_user_id: technician.to_string(),
        created_at: chrono::Utc::now(),
    };
    match repo.create_routing_rule(&rule).await {
        Ok(()) => Redirect::to(&format!("{ROUTING_PATH}?ok=Rule+added.")).into_response(),
        Err(e) => {
            tracing::error!("could not save routing rule: {e}");
            Redirect::to(&format!("{ROUTING_PATH}?err=That+could+not+be+saved.")).into_response()
        }
    }
}

/// `POST /settings/routing-rules/{id}/delete`
pub async fn delete(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(repo) = state.routing_rules.clone() else {
        return not_available();
    };
    match repo.delete_routing_rule(&id).await {
        Ok(()) => Redirect::to(&format!("{ROUTING_PATH}?ok=Rule+deleted.")).into_response(),
        Err(e) => {
            tracing::error!("could not delete routing rule {id}: {e}");
            Redirect::to(&format!("{ROUTING_PATH}?err=That+could+not+be+deleted.")).into_response()
        }
    }
}

/// `(sourced_id, name)` for every school.
async fn school_names(state: &Arc<AppState>) -> Vec<(String, String)> {
    state
        .repo
        .list_orgs()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|o| matches!(o.org_type, chalk_core::models::common::OrgType::School))
        .map(|o| (o.sourced_id, o.name))
        .collect()
}

#[cfg(test)]
mod tests;
