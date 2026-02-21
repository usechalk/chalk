//! Axum routes for the IDP.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::QrBadgeRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::models::idp::QrBadge;
use chrono::Utc;
use serde::Deserialize;

/// Shared state for IDP routes.
pub struct IdpState {
    pub repo: Arc<SqliteRepository>,
    pub config: ChalkConfig,
}

/// Build the IDP Axum router.
pub fn router(state: Arc<IdpState>) -> Router {
    Router::new()
        .route("/saml/metadata", get(saml_metadata))
        .route("/login", get(login_page))
        .route("/login/password", post(login_password))
        .route("/login/qr", post(login_qr))
        .route("/login/qr-scan", get(login_qr_page))
        .route("/login/picture", post(login_picture))
        .route("/login/picture-select", get(login_picture_page))
        .route("/badges/user/:user_id", get(list_badges))
        .route("/badges/user/:user_id/generate", post(generate_badge))
        .route("/badges/revoke/:badge_id", post(revoke_badge))
        .with_state(state)
}

// -- Templates --

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    qr_badge_enabled: bool,
    picture_passwords_enabled: bool,
    relay_state: Option<String>,
    saml_request_id: Option<String>,
}

#[derive(Template)]
#[template(path = "login_qr.html")]
struct LoginQrTemplate;

#[derive(Template)]
#[template(path = "login_picture.html")]
struct LoginPictureTemplate {
    pictures: Vec<String>,
}

#[derive(Template)]
#[template(path = "login_error.html")]
struct LoginErrorTemplate {
    message: String,
}

#[derive(Template)]
#[template(path = "saml_post_binding.html")]
struct SamlPostBindingTemplate {
    acs_url: String,
    saml_response_b64: String,
    relay_state: Option<String>,
}

// -- Form payloads --

#[derive(Deserialize)]
pub struct PasswordLoginForm {
    pub username: String,
    pub password: String,
    pub relay_state: Option<String>,
    pub saml_request_id: Option<String>,
}

#[derive(Deserialize)]
pub struct QrLoginForm {
    pub badge_token: String,
}

#[derive(Deserialize)]
pub struct PictureLoginForm {
    pub username: String,
    pub image_sequence: String,
}

// -- Handlers --

async fn saml_metadata(State(state): State<Arc<IdpState>>) -> Response {
    let entity_id = state
        .config
        .chalk
        .public_url
        .as_deref()
        .unwrap_or("https://chalk.local");
    let sso_url = format!("{}/idp/login", entity_id);

    // Read cert from configured path, or return placeholder
    let cert_pem = match &state.config.idp.saml_cert_path {
        Some(path) => std::fs::read_to_string(path).unwrap_or_default(),
        None => String::new(),
    };

    let xml = crate::saml::generate_metadata(entity_id, &sso_url, &cert_pem);

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/samlmetadata+xml",
        )],
        xml,
    )
        .into_response()
}

async fn login_page(State(state): State<Arc<IdpState>>) -> impl IntoResponse {
    let template = LoginTemplate {
        qr_badge_enabled: state.config.idp.qr_badge_login,
        picture_passwords_enabled: state.config.idp.picture_passwords,
        relay_state: None,
        saml_request_id: None,
    };
    Html(template.render().unwrap_or_default())
}

async fn login_qr_page() -> impl IntoResponse {
    let template = LoginQrTemplate;
    Html(template.render().unwrap_or_default())
}

async fn login_picture_page() -> impl IntoResponse {
    let template = LoginPictureTemplate {
        pictures: crate::picture::PICTURE_OPTIONS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    Html(template.render().unwrap_or_default())
}

fn render_error(message: &str) -> Response {
    let template = LoginErrorTemplate {
        message: message.to_string(),
    };
    Html(template.render().unwrap_or_default()).into_response()
}

fn build_saml_post_response(
    state: &IdpState,
    user_email: &str,
    relay_state: Option<String>,
    request_id: Option<&str>,
) -> Option<Response> {
    let google_config = state.config.idp.google.as_ref()?;
    let entity_id = state
        .config
        .chalk
        .public_url
        .as_deref()
        .unwrap_or("https://chalk.local");

    let saml_response = crate::saml::build_saml_response(
        user_email,
        entity_id,
        &google_config.google_acs_url,
        &google_config.google_entity_id,
        request_id,
    );
    let saml_response_b64 = BASE64.encode(saml_response.as_bytes());

    let template = SamlPostBindingTemplate {
        acs_url: google_config.google_acs_url.clone(),
        saml_response_b64,
        relay_state,
    };
    Some(Html(template.render().unwrap_or_default()).into_response())
}

async fn login_password(
    State(state): State<Arc<IdpState>>,
    Form(form): Form<PasswordLoginForm>,
) -> Response {
    match crate::auth::authenticate_password(state.repo.as_ref(), &form.username, &form.password)
        .await
    {
        Ok(user) => {
            let email = user.email.as_deref().unwrap_or(&user.username);
            // Try SAML response first, fall back to success message
            if let Some(response) = build_saml_post_response(
                &state,
                email,
                form.relay_state,
                form.saml_request_id.as_deref(),
            ) {
                response
            } else {
                Html(format!("Login successful for {}", user.username)).into_response()
            }
        }
        Err(e) => render_error(&e.to_string()),
    }
}

async fn login_qr(State(state): State<Arc<IdpState>>, Form(form): Form<QrLoginForm>) -> Response {
    match crate::auth::authenticate_qr_badge(state.repo.as_ref(), &form.badge_token).await {
        Ok(user) => {
            let email = user.email.as_deref().unwrap_or(&user.username);
            if let Some(response) = build_saml_post_response(&state, email, None, None) {
                response
            } else {
                Html(format!("Login successful for {}", user.username)).into_response()
            }
        }
        Err(e) => render_error(&e.to_string()),
    }
}

async fn login_picture(
    State(state): State<Arc<IdpState>>,
    Form(form): Form<PictureLoginForm>,
) -> Response {
    let sequence: Vec<String> = form
        .image_sequence
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    match crate::auth::authenticate_picture_password(state.repo.as_ref(), &form.username, &sequence)
        .await
    {
        Ok(user) => {
            let email = user.email.as_deref().unwrap_or(&user.username);
            if let Some(response) = build_saml_post_response(&state, email, None, None) {
                response
            } else {
                Html(format!("Login successful for {}", user.username)).into_response()
            }
        }
        Err(e) => render_error(&e.to_string()),
    }
}

async fn generate_badge(
    State(state): State<Arc<IdpState>>,
    Path(user_id): Path<String>,
) -> Response {
    let badge_token = crate::qr::generate_badge_token();
    let badge = QrBadge {
        id: 0,
        badge_token: badge_token.clone(),
        user_sourced_id: user_id,
        is_active: true,
        created_at: Utc::now(),
        revoked_at: None,
    };

    match state.repo.create_badge(&badge).await {
        Ok(_id) => {
            let qr_data = format!("chalk-badge:{}", badge_token);
            match crate::qr::generate_qr_png(&qr_data) {
                Ok(png) => ([(axum::http::header::CONTENT_TYPE, "image/png")], png).into_response(),
                Err(e) => render_error(&e.to_string()),
            }
        }
        Err(e) => render_error(&e.to_string()),
    }
}

async fn list_badges(State(state): State<Arc<IdpState>>, Path(user_id): Path<String>) -> Response {
    match state.repo.list_badges_for_user(&user_id).await {
        Ok(badges) => axum::Json(badges).into_response(),
        Err(e) => render_error(&e.to_string()),
    }
}

async fn revoke_badge(State(state): State<Arc<IdpState>>, Path(badge_id): Path<i64>) -> Response {
    match state.repo.revoke_badge(badge_id).await {
        Ok(true) => Html("Badge revoked".to_string()).into_response(),
        Ok(false) => render_error("Badge not found"),
        Err(e) => render_error(&e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chalk_core::config::{ChalkConfig, ChalkSection, DatabaseConfig, IdpConfig, SisConfig};
    use chalk_core::db::DatabasePool;
    use tower::ServiceExt;

    async fn setup_state() -> Arc<IdpState> {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        let repo = match pool {
            DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        };
        let config = ChalkConfig {
            chalk: ChalkSection {
                instance_name: "Test".into(),
                data_dir: "/tmp".into(),
                public_url: Some("https://chalk.test".into()),
                database: DatabaseConfig::default(),
                telemetry: Default::default(),
            },
            sis: SisConfig::default(),
            idp: IdpConfig {
                enabled: true,
                qr_badge_login: true,
                picture_passwords: true,
                saml_cert_path: None,
                saml_key_path: None,
                session_timeout_minutes: 480,
                google: None,
            },
            google_sync: Default::default(),
            agent: Default::default(),
            marketplace: Default::default(),
        };
        Arc::new(IdpState { repo, config })
    }

    #[tokio::test]
    async fn login_page_returns_200() {
        let state = setup_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn saml_metadata_returns_xml() {
        let state = setup_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/saml/metadata")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("samlmetadata+xml"));
    }

    #[tokio::test]
    async fn qr_scan_page_returns_200() {
        let state = setup_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login/qr-scan")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn picture_page_returns_200() {
        let state = setup_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login/picture-select")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn password_login_invalid_returns_error() {
        let state = setup_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/password")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("username=nouser&password=nopass"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("Login Error"));
    }

    #[tokio::test]
    async fn qr_login_invalid_returns_error() {
        let state = setup_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/qr")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("badge_token=invalid-token"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Login Error"));
    }

    #[tokio::test]
    async fn list_badges_nonexistent_user() {
        let state = setup_state().await;
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/badges/user/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
