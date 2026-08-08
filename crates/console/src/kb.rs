//! Knowledge base — console authoring and the portal's self-service reading
//! surface (WS-11).
//!
//! Two audiences, one table. Technicians write and manage articles in the
//! console at `/kb`, including drafts. The staff help portal lists **published
//! articles only** at `/help/kb`, readable without any sign-in — nothing in an
//! article is personal, and requiring a session to read "how to join the wifi"
//! would defeat the point. The published/draft boundary is enforced in SQL by
//! `list_kb_articles(published_only)` and re-checked per-article on the portal
//! read path.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chalk_core::models::kb::KbArticle;
use serde::Deserialize;

use crate::AppState;

pub const KB_PATH: &str = "/kb";
pub const PORTAL_KB_PATH: &str = "/help/kb";

// ---------------------------------------------------------------------------
// Console: authoring
// ---------------------------------------------------------------------------

pub struct ArticleRow {
    pub id: String,
    pub title: String,
    pub published: bool,
    pub updated: String,
}

struct Flash {
    kind: String,
    message: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "kb/index.html")]
struct KbIndexTemplate {
    nav: crate::nav::Nav,
    articles: Vec<ArticleRow>,
    flash: Option<Flash>,
    csrf_token: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "kb/edit.html")]
struct KbEditTemplate {
    nav: crate::nav::Nav,
    id: String,
    title: String,
    body: String,
    published: bool,
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
        Html("<h1>The knowledge base is not available on this build.</h1>".to_string()),
    )
        .into_response()
}

fn article_not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Html(
            "<h1>No such article</h1><p><a href=\"/kb\">Back to the knowledge base</a></p>"
                .to_string(),
        ),
    )
        .into_response()
}

/// `GET /kb` — every article, drafts included, newest first.
pub async fn index(
    State(state): State<Arc<AppState>>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
    Query(flash_q): Query<FlashQuery>,
) -> Response {
    let Some(repo) = state.kb.clone() else {
        return not_available();
    };
    let articles = repo
        .list_kb_articles(false)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| ArticleRow {
            id: a.id,
            title: a.title,
            published: a.published,
            updated: a.updated_at.format("%Y-%m-%d %H:%M").to_string(),
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
    KbIndexTemplate {
        nav: crate::nav::Nav::new(&state.config, "kb"),
        articles,
        flash,
        csrf_token: csrf.0,
    }
    .into_response()
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ArticleForm {
    title: String,
    body: String,
    /// `"1"` publishes; anything else keeps or returns it to draft.
    published: String,
}

/// `POST /kb` — create an article. Publishing is a checkbox on the same form,
/// but a new article defaults to draft.
pub async fn create(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<ArticleForm>,
) -> Response {
    let Some(repo) = state.kb.clone() else {
        return not_available();
    };
    let title = form.title.trim();
    let body = form.body.trim();
    if title.is_empty() || body.is_empty() {
        return Redirect::to(&format!(
            "{KB_PATH}?err=A+title+and+a+body+are+both+required."
        ))
        .into_response();
    }
    let mut article = KbArticle::draft(uuid::Uuid::new_v4().to_string(), title, body);
    article.published = form.published.trim() == "1";
    match repo.create_kb_article(&article).await {
        Ok(()) => Redirect::to(&format!("{KB_PATH}?ok=Saved.")).into_response(),
        Err(e) => {
            tracing::error!("could not save KB article: {e}");
            Redirect::to(&format!("{KB_PATH}?err=That+could+not+be+saved.")).into_response()
        }
    }
}

/// `GET /kb/{id}` — the edit form.
pub async fn edit_page(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Extension(csrf): axum::Extension<crate::csrf::CsrfToken>,
) -> Response {
    let Some(repo) = state.kb.clone() else {
        return not_available();
    };
    match repo.get_kb_article(&id).await {
        Ok(Some(a)) => KbEditTemplate {
            nav: crate::nav::Nav::new(&state.config, "kb"),
            id: a.id,
            title: a.title,
            body: a.body,
            published: a.published,
            csrf_token: csrf.0,
        }
        .into_response(),
        Ok(None) => article_not_found(),
        Err(e) => {
            tracing::error!("could not load KB article {id}: {e}");
            article_not_found()
        }
    }
}

/// `POST /kb/{id}` — update title/body/published.
pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<ArticleForm>,
) -> Response {
    let Some(repo) = state.kb.clone() else {
        return not_available();
    };
    let Ok(Some(mut article)) = repo.get_kb_article(&id).await else {
        return article_not_found();
    };
    let title = form.title.trim();
    let body = form.body.trim();
    if title.is_empty() || body.is_empty() {
        return Redirect::to(&format!(
            "{KB_PATH}?err=A+title+and+a+body+are+both+required."
        ))
        .into_response();
    }
    article.title = title.to_string();
    article.body = body.to_string();
    article.published = form.published.trim() == "1";
    match repo.update_kb_article(&article).await {
        Ok(()) => Redirect::to(&format!("{KB_PATH}?ok=Saved.")).into_response(),
        Err(e) => {
            tracing::error!("could not update KB article {id}: {e}");
            Redirect::to(&format!("{KB_PATH}?err=That+could+not+be+saved.")).into_response()
        }
    }
}

/// `POST /kb/{id}/delete`
pub async fn delete(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some(repo) = state.kb.clone() else {
        return not_available();
    };
    match repo.delete_kb_article(&id).await {
        Ok(()) => Redirect::to(&format!("{KB_PATH}?ok=Deleted.")).into_response(),
        Err(e) => {
            tracing::error!("could not delete KB article {id}: {e}");
            Redirect::to(&format!("{KB_PATH}?err=That+could+not+be+deleted.")).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Portal: reading
// ---------------------------------------------------------------------------

pub struct PortalArticle {
    pub id: String,
    pub title: String,
    pub updated: String,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "help/kb_index.html")]
struct PortalKbIndexTemplate {
    articles: Vec<PortalArticle>,
}

#[derive(Template, askama_web::WebTemplate)]
#[template(path = "help/kb_article.html")]
struct PortalKbArticleTemplate {
    title: String,
    body: String,
    updated: String,
}

/// `GET /help/kb` — published articles, no sign-in required.
pub async fn portal_index(State(state): State<Arc<AppState>>) -> Response {
    let Some(repo) = state.kb.clone() else {
        return not_available();
    };
    let articles = repo
        .list_kb_articles(true)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| PortalArticle {
            id: a.id,
            title: a.title,
            updated: a.updated_at.format("%Y-%m-%d").to_string(),
        })
        .collect();
    PortalKbIndexTemplate { articles }.into_response()
}

/// `GET /help/kb/{id}` — one published article. A draft is a 404 here, not a
/// preview: the portal must be incapable of showing unfinished work.
pub async fn portal_article(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let Some(repo) = state.kb.clone() else {
        return not_available();
    };
    match repo.get_kb_article(&id).await {
        Ok(Some(a)) if a.published => PortalKbArticleTemplate {
            title: a.title,
            body: a.body,
            updated: a.updated_at.format("%Y-%m-%d").to_string(),
        }
        .into_response(),
        _ => (
            axum::http::StatusCode::NOT_FOUND,
            Html(
                "<h1>No such article</h1><p><a href=\"/help/kb\">Back to help articles</a></p>"
                    .to_string(),
            ),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests;
