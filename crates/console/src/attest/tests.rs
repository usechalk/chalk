//! Attestation-campaign tests: a campaign asks once per open loan, the
//! public form answers once, "no" surfaces as the finding, and re-runs nag
//! rather than duplicate.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{
    AssetEventRepository, AssetRepository, AttestationRepository, ChalkRepository,
    CustodyRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::mail::{EmailMessage, Notifier};
use chalk_core::models::asset::Asset;
use chalk_core::models::common::{RoleType, Status};
use chalk_core::models::custody::CustodyRecord;
use chalk_core::models::user::User;
use chrono::Utc;
use std::sync::Mutex;
use tower::ServiceExt;

use crate::router;

/// A mailer that records instead of sending.
struct SpyMailer {
    sent: Mutex<Vec<EmailMessage>>,
}

#[async_trait::async_trait]
impl Notifier for SpyMailer {
    async fn send_email(&self, message: &EmailMessage) -> anyhow::Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
}

struct Fx {
    state: Arc<AppState>,
    repo: Arc<SqliteRepository>,
    mailer: Arc<SpyMailer>,
}

async fn fixture() -> Fx {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let repo = match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    };
    repo.upsert_user(&User {
        sourced_id: "u-maya".into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        username: "maya.chen".into(),
        user_ids: vec![],
        enabled_user: true,
        given_name: "Maya".into(),
        family_name: "Chen".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some("maya.chen@example.edu".into()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec![],
        grades: vec![],
    })
    .await
    .unwrap();

    let mut a = Asset::new("dev-1");
    a.asset_tag = Some("CB-0001".into());
    repo.create_asset(&a).await.unwrap();
    repo.create_custody(&CustodyRecord {
        id: "loan-1".into(),
        asset_id: "dev-1".into(),
        user_sourced_id: "u-maya".into(),
        checked_out_at: Utc::now(),
        due_at: None,
        checked_in_at: None,
        condition_out: None,
        condition_in: None,
        agreement_acknowledged: true,
        actor: "console:admin".into(),
        loaner: false,
        signature_png: None,
        signed_at: None,
    })
    .await
    .unwrap();

    let mailer = Arc::new(SpyMailer {
        sent: Mutex::new(Vec::new()),
    });
    let mut config = ChalkConfig::generate_default();
    config.chalk.public_url = Some("https://console.district.test".into());
    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let assets: Arc<dyn AssetRepository> = repo.clone();
    let events: Arc<dyn AssetEventRepository> = repo.clone();
    let custody: Arc<dyn CustodyRepository> = repo.clone();
    let attest: Arc<dyn AttestationRepository> = repo.clone();
    let state = Arc::new(
        AppState::new(chalk_repo, config)
            .with_assets(assets, events)
            .with_custody(custody)
            .with_attestations(attest)
            .with_mailer(mailer.clone()),
    );
    Fx {
        state,
        repo,
        mailer,
    }
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

async fn post(state: Arc<AppState>, uri: &str, body: &str) -> (StatusCode, String, String) {
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
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        location,
        String::from_utf8_lossy(&bytes).to_string(),
    )
}

/// The whole loop: start a campaign → one ask per open loan, one email with
/// the link → the public form answers "no, broken" → the campaign table
/// shows the finding with the danger badge.
#[tokio::test]
async fn a_campaign_asks_emails_and_records_the_answer() {
    let f = fixture().await;

    let (status, location, _) = post(f.state.clone(), "/devices/attestations/start", "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.contains("notice=started"), "got {location}");

    let asks = f.repo.list_attestations().await.unwrap();
    assert_eq!(asks.len(), 1, "one ask for the one open loan");
    let sent = f.mailer.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, "maya.chen@example.edu");
    assert!(sent[0].subject.contains("CB-0001"), "the device is named");
    assert!(
        sent[0].body.contains(&format!("/attest/{}", asks[0].token)),
        "the link carries the token"
    );

    // The public form renders for the token.
    let (status, html) = get(f.state.clone(), &format!("/attest/{}", asks[0].token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("CB-0001"));

    // Answer: no, broken, with a note.
    let (status, _, html) = post(
        f.state.clone(),
        &format!("/attest/{}", asks[0].token),
        "have=no&condition=broken&note=left+it+on+the+bus&csrf_token=x",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Recorded"));

    let a = f
        .repo
        .get_attestation_by_token(&asks[0].token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.has_item, Some(false));
    assert_eq!(
        a.condition,
        Some(chalk_core::models::attestation::AttestCondition::Broken)
    );
    assert_eq!(a.note.as_deref(), Some("left it on the bus"));

    // The console table shows the finding.
    let (_, page) = get(f.state.clone(), "/devices/attestations").await;
    assert!(page.contains("Does not have it"));
    assert!(page.contains("left it on the bus"));
}

/// First answer wins, and a re-visited link says so politely.
#[tokio::test]
async fn a_second_answer_is_refused_politely() {
    let f = fixture().await;
    post(f.state.clone(), "/devices/attestations/start", "").await;
    let token = f.repo.list_attestations().await.unwrap()[0].token.clone();
    post(
        f.state.clone(),
        &format!("/attest/{token}"),
        "have=yes&condition=good&csrf_token=x",
    )
    .await;

    let (_, _, html) = post(
        f.state.clone(),
        &format!("/attest/{token}"),
        "have=no&condition=broken&csrf_token=x",
    )
    .await;
    assert!(html.contains("Already answered"));
    let a = f
        .repo
        .get_attestation_by_token(&token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.has_item, Some(true), "the first answer stands");

    let (_, html) = get(f.state.clone(), &format!("/attest/{token}")).await;
    assert!(html.contains("Already answered"));
}

/// Re-running a campaign nags instead of duplicating: no second ask row for
/// a loan that already has a pending one, but the reminder email goes out.
#[tokio::test]
async fn a_rerun_nags_without_duplicating() {
    let f = fixture().await;
    post(f.state.clone(), "/devices/attestations/start", "").await;
    let (_, location, _) = post(f.state.clone(), "/devices/attestations/start", "").await;
    assert!(location.contains("notice=nothing"), "got {location}");
    assert_eq!(f.repo.list_attestations().await.unwrap().len(), 1);

    let before = f.mailer.sent.lock().unwrap().len();
    let (_, location, _) = post(f.state.clone(), "/devices/attestations/resend", "").await;
    assert!(location.contains("notice=resent"));
    assert_eq!(
        f.mailer.sent.lock().unwrap().len(),
        before + 1,
        "the reminder went out"
    );
}

/// An unknown token ends politely — an email link must never dead-end.
#[tokio::test]
async fn an_unknown_token_ends_politely() {
    let f = fixture().await;
    let (status, html) = get(f.state.clone(), "/attest/nope").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("no longer active"));
}
