//! The dashboard through the real router: widgets from saved reports, the
//! tokened share that renders without a session and dies on revocation, and
//! the digest email carrying the same numbers.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::db::repository::{
    AdminSessionRepository, AssetReportRepository, AssetRepository, DashboardShareRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::audit::AdminSession;
use chrono::Duration;
use std::sync::Mutex;
use tower::ServiceExt;

struct CapturingNotifier {
    sent: Mutex<Vec<(String, String, String)>>,
}

#[async_trait::async_trait]
impl chalk_core::mail::Notifier for CapturingNotifier {
    async fn send_email(&self, m: &chalk_core::mail::EmailMessage) -> anyhow::Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((m.to.clone(), m.subject.clone(), m.body.clone()));
        Ok(())
    }
}

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
    mail: Arc<CapturingNotifier>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let mut config = crate::tests::default_config();
    config.chalk.admin_password_hash = Some(crate::auth::hash_password("unused").unwrap());
    config.chalk.alerts_email = Some("ops@district.test".into());
    let mail = Arc::new(CapturingNotifier {
        sent: Mutex::new(Vec::new()),
    });
    let state = Arc::new(crate::tests::wire_all(repo.clone(), config).with_mailer(mail.clone()));
    repo.create_admin_session(&AdminSession {
        token: "adm".into(),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        actor_id: None,
        actor_label: None,
        actor_role: None,
    })
    .await
    .unwrap();
    // Two devices and one saved report so a widget exists.
    for (id, status) in [("d1", "active"), ("d2", "repair")] {
        let mut a = chalk_core::models::asset::Asset::new(id);
        a.asset_tag = Some(format!("CB-{id}"));
        a.status = chalk_core::models::asset::AssetStatus::parse(status).unwrap();
        repo.create_asset(&a).await.unwrap();
    }
    repo.create_asset_report(&chalk_core::models::report::AssetReport {
        id: "rep-1".into(),
        name: "Fleet by status".into(),
        query: String::new(),
        group_by: chalk_core::models::report::ReportDimension::Status,
        actor: "test".into(),
        created_at: Utc::now(),
    })
    .await
    .unwrap();
    Fx { state, repo, mail }
}

async fn get(fx: &Fx, uri: &str, session: bool) -> (StatusCode, String) {
    let mut b = Request::builder().uri(uri);
    if session {
        b = b.header("cookie", "chalk_session=adm");
    }
    let res = crate::router(fx.state.clone())
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).to_string())
}

async fn post(fx: &Fx, uri: &str) -> StatusCode {
    let csrf = crate::csrf::generate_csrf_token();
    let res = crate::router(fx.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("chalk_session=adm; chalk_csrf={csrf}"))
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    res.status()
}

/// Session view: stats and the saved-report widget render.
#[tokio::test]
async fn the_dashboard_composes_stats_and_report_widgets() {
    let fx = fixture().await;
    let (status, html) = get(&fx, "/devices/dashboard", true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Fleet by status"),
        "widget from the saved report"
    );
    assert!(html.contains("active") && html.contains("repair"));
    assert!(html.contains("Devices"), "the stat cards render");
    assert!(html.contains("Create a share link"));
}

/// The share loop: mint, open without a session, revoke, gone. The shared
/// page must carry no console links.
#[tokio::test]
async fn a_share_link_is_read_only_and_dies_on_revocation() {
    let fx = fixture().await;
    post(&fx, "/devices/dashboard/share").await;
    let token = fx.repo.list_dashboard_shares().await.unwrap()[0].clone();

    let (status, html) = get(&fx, &format!("/share/dashboard/{token}"), false).await;
    assert_eq!(status, StatusCode::OK, "no session needed");
    assert!(html.contains("Fleet by status"));
    assert!(
        !html.contains("Create a share link") && !html.contains("href=\"/devices\""),
        "the shared view must carry no console affordances"
    );
    assert!(!html.contains("CB-d1"), "counts only — never device rows");

    // A wrong token is a 404, and a revoked one becomes a wrong token.
    let (status, _) = get(&fx, "/share/dashboard/nope", false).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    post(&fx, &format!("/devices/dashboard/share/{token}/revoke")).await;
    let (status, _) = get(&fx, &format!("/share/dashboard/{token}"), false).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The digest email carries the same numbers the page shows.
#[tokio::test]
async fn the_digest_emails_the_dashboard_numbers() {
    let fx = fixture().await;
    let status = post(&fx, "/devices/dashboard/email").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let sent = fx.mail.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    let (to, subject, body) = &sent[0];
    assert_eq!(to, "ops@district.test");
    assert!(subject.contains("digest"));
    assert!(body.contains("Devices: 2"));
    assert!(body.contains("Fleet by status"));
    assert!(body.contains("active: 1"));
}
