//! CSAT tests: resolving sends exactly one survey, the rating link records the
//! first answer only, and the analytics page shows the aggregate.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, CsatRepository, TicketRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::ticket::Ticket;
use tower::ServiceExt;

use crate::router;

#[derive(Default)]
struct CapturingNotifier {
    sent: std::sync::Mutex<Vec<EmailMessage>>,
}

#[async_trait::async_trait]
impl chalk_core::mail::Notifier for CapturingNotifier {
    async fn send_email(&self, message: &EmailMessage) -> anyhow::Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
}

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
    notifier: Arc<CapturingNotifier>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    let notifier = Arc::new(CapturingNotifier::default());
    let mut config = ChalkConfig::generate_default();
    config.chalk.public_url = Some("https://help.example.edu".into());

    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let csat: Arc<dyn CsatRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = AppState::new(chalk_repo, config)
        .with_tickets(tickets)
        .with_csat(csat)
        .with_mailer(notifier.clone());
    Fx {
        state: Arc::new(state),
        repo,
        notifier,
    }
}

/// A ticket from an email-only requester, so the survey address needs no
/// roster.
async fn ticket(f: &Fx, id: &str) -> Ticket {
    let mut t = Ticket::new(id, format!("Subject {id}"));
    t.requester_email = Some("parent@family.test".into());
    f.repo.create_ticket(&t).await.unwrap()
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

async fn post(state: Arc<AppState>, uri: &str, body: &str) -> StatusCode {
    let token = crate::csrf::generate_csrf_token();
    router(state)
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
        .unwrap()
        .status()
}

/// The token from the last survey email — the links carry
/// `/csat/{token}/{score}`.
fn token_from(notifier: &CapturingNotifier) -> String {
    let sent = notifier.sent.lock().unwrap();
    let body = &sent.last().expect("a survey was sent").body;
    let marker = "/csat/";
    let start = body.find(marker).expect("a rating link") + marker.len();
    body[start..]
        .split('/')
        .next()
        .expect("token segment")
        .to_string()
}

/// Resolving sends exactly one survey, however many times it is resolved.
#[tokio::test]
async fn resolving_sends_one_survey_and_only_one() {
    let f = fixture().await;
    let t = ticket(&f, "t-1").await;

    let status = post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=resolved",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    {
        let sent = f.notifier.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "one survey");
        assert_eq!(sent[0].to, "parent@family.test");
        assert!(sent[0].subject.contains("How did we do?"));
        assert!(
            sent[0].body.contains("https://help.example.edu/csat/"),
            "carries rating links"
        );
    }

    // Reopen, resolve again: no second ask.
    post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=open",
    )
    .await;
    post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=resolved",
    )
    .await;
    assert_eq!(
        f.notifier.sent.lock().unwrap().len(),
        1,
        "a re-resolve is not a second survey"
    );
}

/// The rating link records the first answer only, politely acknowledges the
/// second, and rejects scores off the scale — all without any session.
#[tokio::test]
async fn the_rating_link_records_the_first_answer_only() {
    let f = fixture().await;
    let t = ticket(&f, "t-1").await;
    post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=resolved",
    )
    .await;
    let token = token_from(&f.notifier);

    let (status, body) = get(f.state.clone(), &format!("/csat/{token}/5")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("your rating was recorded"));

    // A second click does not rewrite the score.
    let (_, body) = get(f.state.clone(), &format!("/csat/{token}/1")).await;
    assert!(body.contains("already recorded"));
    let survey = f.repo.get_csat_by_token(&token).await.unwrap().unwrap();
    assert_eq!(survey.score, Some(5), "the first answer stands");

    // Off the scale and unknown tokens end politely, not with an error page.
    let (status, body) = get(f.state.clone(), &format!("/csat/{token}/9")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("not a valid rating"));
    let (status, body) = get(f.state.clone(), "/csat/nonsense-token/3").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("no longer valid"));
}

/// The analytics page shows the aggregate once a survey exists.
#[tokio::test]
async fn analytics_shows_the_average_once_surveys_exist() {
    let f = fixture().await;
    let t = ticket(&f, "t-1").await;
    post(
        f.state.clone(),
        &format!("/tickets/{}/status", t.id),
        "status=resolved",
    )
    .await;
    let token = token_from(&f.notifier);
    get(f.state.clone(), &format!("/csat/{token}/4")).await;

    let (status, body) = get(f.state.clone(), "/tickets/analytics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Satisfaction"), "the card appears");
    assert!(body.contains("4.0 / 5"), "the average is shown");
    assert!(body.contains("1</span>"), "responded count");
}

/// With no public URL there is nowhere for the links to point, so no survey is
/// sent — same rule as the reply notification.
#[tokio::test]
async fn no_public_url_means_no_survey() {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!(),
    };
    let notifier = Arc::new(CapturingNotifier::default());
    let config = ChalkConfig::generate_default(); // no public_url
    let tickets: Arc<dyn TicketRepository> = repo.clone();
    let csat: Arc<dyn CsatRepository> = repo.clone();
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, config)
            .with_tickets(tickets)
            .with_csat(csat)
            .with_mailer(notifier.clone()),
    );
    let mut t = Ticket::new("t-1", "Subject");
    t.requester_email = Some("parent@family.test".into());
    repo.create_ticket(&t).await.unwrap();

    post(state.clone(), "/tickets/t-1/status", "status=resolved").await;
    assert!(notifier.sent.lock().unwrap().is_empty(), "nothing sent");
}
