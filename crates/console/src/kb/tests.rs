//! Knowledge-base tests. The one that matters most: a draft must never appear
//! on the portal — the published/draft boundary is the whole design.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, KbRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use tower::ServiceExt;

use crate::router;

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    let kb: Arc<dyn KbRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(AppState::new(chalk_repo, ChalkConfig::generate_default()).with_kb(kb));
    Fx { state, repo }
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, String) {
    let res = router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn post(state: Arc<AppState>, uri: &str, body: &str) -> (StatusCode, String) {
    let token = crate::csrf::generate_csrf_token();
    let res = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("chalk_csrf={token}"))
                .header("x-csrf-token", &token)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, location)
}

/// Author, publish, edit, delete — the whole console lifecycle.
#[tokio::test]
async fn an_article_is_authored_edited_and_deleted() {
    let f = fixture().await;

    let (status, location) = post(
        f.state.clone(),
        "/kb",
        "title=Join+the+wifi&body=Pick+the+STAFF+network.&published=1",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("ok="));

    let (_, page) = get(f.state.clone(), "/kb").await;
    assert!(page.contains("Join the wifi"));
    assert!(page.contains("Published"));

    let id = f.repo.list_kb_articles(false).await.unwrap()[0].id.clone();
    // Edit back to draft.
    let (status, _) = post(
        f.state.clone(),
        &format!("/kb/{id}"),
        "title=Join+the+wifi&body=Pick+the+STAFF+network.",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let article = f.repo.get_kb_article(&id).await.unwrap().unwrap();
    assert!(!article.published, "unchecking the box unpublishes");

    let (status, _) = post(f.state.clone(), &format!("/kb/{id}/delete"), "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(f.repo.list_kb_articles(false).await.unwrap().is_empty());
}

/// The disclosure boundary: the portal lists and serves published articles
/// only. A draft is a 404 there, indistinguishable from an article that does
/// not exist — never a preview.
#[tokio::test]
async fn a_draft_never_appears_on_the_portal() {
    let f = fixture().await;
    post(
        f.state.clone(),
        "/kb",
        "title=Published+one&body=Visible.&published=1",
    )
    .await;
    post(f.state.clone(), "/kb", "title=Draft+one&body=Hidden.").await;

    // The portal list, with no session of any kind.
    let (status, list) = get(f.state.clone(), "/help/kb").await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.contains("Published one"));
    assert!(!list.contains("Draft one"), "drafts never reach the portal");

    // The draft by direct URL is a 404, same as a nonsense id.
    let articles = f.repo.list_kb_articles(false).await.unwrap();
    let draft_id = articles
        .iter()
        .find(|a| !a.published)
        .map(|a| a.id.clone())
        .unwrap();
    let (status, _) = get(f.state.clone(), &format!("/help/kb/{draft_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (nonsense, _) = get(f.state.clone(), "/help/kb/nope").await;
    assert_eq!(nonsense, StatusCode::NOT_FOUND, "the same answer");

    // The published one reads fine.
    let published_id = articles
        .iter()
        .find(|a| a.published)
        .map(|a| a.id.clone())
        .unwrap();
    let (status, page) = get(f.state.clone(), &format!("/help/kb/{published_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Visible."));
}

/// A blank title or body is refused.
#[tokio::test]
async fn a_blank_article_is_refused() {
    let f = fixture().await;
    let (_, location) = post(f.state.clone(), "/kb", "title=&body=something").await;
    assert!(location.contains("err="));
    assert!(f.repo.list_kb_articles(false).await.unwrap().is_empty());
}
