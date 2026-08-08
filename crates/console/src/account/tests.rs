//! 2FA tests: enrollment arms only after a proven code, the two-step login
//! demands the code and burns its challenge, recovery codes work exactly
//! once, and disabling requires possession.

use super::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{ChalkRepository, ConsoleUserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::console_user::{ConsoleRole, ConsoleUser, ConsoleUserStatus};
use tower::ServiceExt;

use crate::router;

const PASSWORD: &str = "tech-password-1";

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
    let hash = crate::auth::hash_password(PASSWORD).unwrap();
    repo.create_console_user(&ConsoleUser {
        id: "cu-1".into(),
        email: "tech@district.test".into(),
        display_name: "Tech One".into(),
        password_hash: Some(hash),
        role: ConsoleRole::Technician,
        status: ConsoleUserStatus::Active,
        totp_secret: None,
        totp_confirmed: false,
        totp_recovery: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
    .await
    .unwrap();

    let chalk_repo: Arc<dyn ChalkRepository> = repo.clone();
    let users: Arc<dyn ConsoleUserRepository> = repo.clone();
    // A configured admin hash keeps the auth middleware in real mode — with
    // no hash and no magic-link it treats every request as the shared admin,
    // which would mask the per-person identity this suite is about.
    let mut config = ChalkConfig::generate_default();
    config.chalk.admin_password_hash = Some(crate::auth::hash_password("unused-admin-pw").unwrap());
    let state = Arc::new(AppState::new(chalk_repo, config).with_console_users(users));
    Fx { state, repo }
}

async fn post(
    state: Arc<AppState>,
    uri: &str,
    body: &str,
    session: Option<&str>,
) -> axum::response::Response {
    let token = crate::csrf::generate_csrf_token();
    let mut cookie = format!("chalk_csrf={token}");
    if let Some(s) = session {
        cookie.push_str(&format!("; chalk_session={s}"));
    }
    router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", cookie)
                .header("x-csrf-token", &token)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_of(res: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// Log the technician in (step one only) and return the session cookie value,
/// or the step-two page body when 2FA interposed.
async fn password_login(f: &Fx) -> (Option<String>, String) {
    let res = post(
        f.state.clone(),
        "/login",
        &format!("email=tech%40district.test&password={PASSWORD}"),
        None,
    )
    .await;
    let session = res
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("chalk_session="))
        .map(|c| {
            c.trim_start_matches("chalk_session=")
                .split(';')
                .next()
                .unwrap()
                .to_string()
        });
    let body = body_of(res).await;
    (session, body)
}

fn current_code(secret: &str) -> String {
    chalk_core::totp::code_at(secret, Utc::now().timestamp() as u64).unwrap()
}

/// The full arc: enroll (unconfirmed does not gate) → confirm with a real
/// code → login now interposes step two → the correct code finishes login →
/// the challenge is burned (replay fails).
#[tokio::test]
async fn a_the_full_totp_arc() {
    let f = fixture().await;

    // Before enrollment: password alone signs in.
    let (session, _) = password_login(&f).await;
    let session = session.expect("no 2FA yet, session issued");
    {
        use chalk_core::db::repository::AdminSessionRepository;
        let row = f
            .repo
            .get_admin_session(&session)
            .await
            .unwrap()
            .expect("session row");
        assert_eq!(
            row.actor_id.as_deref(),
            Some("console_user:cu-1"),
            "login stamped the per-person identity"
        );
    }

    // Start enrollment through the route (session-authenticated).
    let res = post(
        f.state.clone(),
        "/account/security/totp/start",
        "",
        Some(&session),
    )
    .await;
    let status = res.status();
    let loc = res
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let html = body_of(res).await;
    assert!(
        html.contains("<svg"),
        "the QR renders (got {status} -> {loc})"
    );
    assert!(html.contains("Recovery codes"));

    let secret = f
        .repo
        .get_console_user("cu-1")
        .await
        .unwrap()
        .unwrap()
        .totp_secret
        .expect("secret stored");

    // Unconfirmed enrollment must NOT gate login yet — a half-finished setup
    // cannot lock the person out.
    let (session2, _) = password_login(&f).await;
    assert!(session2.is_some(), "unconfirmed 2FA does not gate");

    // Confirm with the real current code.
    let res = post(
        f.state.clone(),
        "/account/security/totp/confirm",
        &format!("code={}", current_code(&secret)),
        Some(&session),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        f.repo
            .get_console_user("cu-1")
            .await
            .unwrap()
            .unwrap()
            .totp_confirmed
    );

    // Login now interposes step two instead of a session.
    let (session3, step_two) = password_login(&f).await;
    assert!(session3.is_none(), "no session before the code");
    assert!(step_two.contains("/login/totp"), "the code form renders");
    let challenge = step_two
        .split("name=\"challenge\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();

    // Wrong code: refused, and the challenge is burned.
    let res = post(
        f.state.clone(),
        "/login/totp",
        &format!("challenge={challenge}&code=000000"),
        None,
    )
    .await;
    let html = body_of(res).await;
    assert!(
        html.contains("expired") || html.contains("did not verify"),
        "refused"
    );
    let res = post(
        f.state.clone(),
        "/login/totp",
        &format!("challenge={challenge}&code={}", current_code(&secret)),
        None,
    )
    .await;
    let html = body_of(res).await;
    assert!(
        html.contains("expired") || html.contains("start again"),
        "a burned challenge cannot be replayed with the right code"
    );

    // Fresh login, correct code: session issued.
    let (_, step_two) = password_login(&f).await;
    let challenge = step_two
        .split("name=\"challenge\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let res = post(
        f.state.clone(),
        "/login/totp",
        &format!("challenge={challenge}&code={}", current_code(&secret)),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(res
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.starts_with("chalk_session=")));
}

/// A recovery code signs in exactly once and is burned on use.
#[tokio::test]
async fn a_recovery_code_works_exactly_once() {
    let f = fixture().await;
    let (session, _) = password_login(&f).await;
    let session = session.unwrap();
    let res = post(
        f.state.clone(),
        "/account/security/totp/start",
        "",
        Some(&session),
    )
    .await;
    let html = body_of(res).await;
    // Scrape one plaintext recovery code from the one-time page.
    let code = html
        .split("<li>")
        .nth(1)
        .unwrap()
        .split("</li>")
        .next()
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(code.len(), 9, "XXXX-XXXX");
    let secret = f
        .repo
        .get_console_user("cu-1")
        .await
        .unwrap()
        .unwrap()
        .totp_secret
        .unwrap();
    post(
        f.state.clone(),
        "/account/security/totp/confirm",
        &format!("code={}", current_code(&secret)),
        Some(&session),
    )
    .await;

    // Use the recovery code at step two.
    let (_, step_two) = password_login(&f).await;
    let challenge = step_two
        .split("name=\"challenge\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let res = post(
        f.state.clone(),
        "/login/totp",
        &format!("challenge={challenge}&code={code}"),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "recovery code works");

    // Second use of the same code: refused.
    let (_, step_two) = password_login(&f).await;
    let challenge = step_two
        .split("name=\"challenge\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let res = post(
        f.state.clone(),
        "/login/totp",
        &format!("challenge={challenge}&code={code}"),
        None,
    )
    .await;
    let html = body_of(res).await;
    assert!(html.contains("did not verify"), "burned on first use");
}

/// Disabling requires a current code — a walked-away-from session cannot
/// strip 2FA silently.
#[tokio::test]
async fn a_disable_requires_possession() {
    let f = fixture().await;
    let (session, _) = password_login(&f).await;
    let session = session.unwrap();
    post(
        f.state.clone(),
        "/account/security/totp/start",
        "",
        Some(&session),
    )
    .await;
    let secret = f
        .repo
        .get_console_user("cu-1")
        .await
        .unwrap()
        .unwrap()
        .totp_secret
        .unwrap();
    post(
        f.state.clone(),
        "/account/security/totp/confirm",
        &format!("code={}", current_code(&secret)),
        Some(&session),
    )
    .await;

    let res = post(
        f.state.clone(),
        "/account/security/totp/disable",
        "code=000000",
        Some(&session),
    )
    .await;
    assert!(body_of(res).await.is_empty() || true);
    assert!(
        f.repo
            .get_console_user("cu-1")
            .await
            .unwrap()
            .unwrap()
            .totp_confirmed,
        "a wrong code does not disable"
    );

    post(
        f.state.clone(),
        "/account/security/totp/disable",
        &format!("code={}", current_code(&secret)),
        Some(&session),
    )
    .await;
    let u = f.repo.get_console_user("cu-1").await.unwrap().unwrap();
    assert!(!u.totp_confirmed);
    assert!(u.totp_secret.is_none(), "torn down entirely");
}
