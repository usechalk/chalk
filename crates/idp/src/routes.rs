//! Axum routes for the IDP.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::header::SET_COOKIE,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chalk_core::config::ChalkConfig;
use chalk_core::db::repository::{PortalSessionRepository, QrBadgeRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::models::idp::QrBadge;
use chalk_core::models::sso::SsoPartner;
use chrono::Utc;
use serde::Deserialize;

/// Shared state for IDP routes.
pub struct IdpState {
    pub repo: Arc<SqliteRepository>,
    pub config: ChalkConfig,
    pub partners: Vec<SsoPartner>,
    pub signing_key: Option<Vec<u8>>,
    pub signing_cert: Option<String>,
}

/// Build the IDP Axum router.
pub fn router(state: Arc<IdpState>) -> Router {
    Router::new()
        .route("/saml/metadata", get(saml_metadata))
        .route("/saml/sso", get(saml_sso))
        .route("/saml/initiate/:partner_id", post(saml_initiate))
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
    partner_id: Option<String>,
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
    pub partner_id: Option<String>,
}

#[derive(Deserialize)]
pub struct QrLoginForm {
    pub badge_token: String,
    pub partner_id: Option<String>,
}

#[derive(Deserialize)]
pub struct PictureLoginForm {
    pub username: String,
    pub image_sequence: String,
    pub partner_id: Option<String>,
}

/// Query params for SP-initiated SAML SSO.
#[derive(Deserialize)]
pub struct SamlSsoQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
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

/// SP-initiated SAML SSO endpoint.
/// Accepts a SAMLRequest query param, parses the AuthnRequest, looks up the SP,
/// and redirects to the login page with SP context.
async fn saml_sso(
    State(state): State<Arc<IdpState>>,
    Query(query): Query<SamlSsoQuery>,
) -> Response {
    let parsed = match crate::saml::parse_authn_request(&query.saml_request) {
        Ok(p) => p,
        Err(e) => return render_error(&format!("Invalid SAMLRequest: {e}")),
    };

    // Look up the SP by matching issuer to a partner's saml_entity_id
    let partner = state.partners.iter().find(|p| {
        p.enabled
            && p.saml_entity_id
                .as_deref()
                .map(|eid| eid == parsed.issuer)
                .unwrap_or(false)
    });

    let partner = match partner {
        Some(p) => p,
        None => return render_error(&format!("Unknown service provider: {}", parsed.issuer)),
    };

    // Redirect to login page with SP context via query params
    let template = LoginTemplate {
        qr_badge_enabled: state.config.idp.qr_badge_login,
        picture_passwords_enabled: state.config.idp.picture_passwords,
        relay_state: query.relay_state,
        saml_request_id: Some(parsed.request_id),
        partner_id: Some(partner.id.clone()),
    };
    Html(template.render().unwrap_or_default()).into_response()
}

async fn login_page(State(state): State<Arc<IdpState>>) -> impl IntoResponse {
    let template = LoginTemplate {
        qr_badge_enabled: state.config.idp.qr_badge_login,
        picture_passwords_enabled: state.config.idp.picture_passwords,
        relay_state: None,
        saml_request_id: None,
        partner_id: None,
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

/// Resolve the target partner for a login attempt.
/// If partner_id is provided, look up from state.partners.
/// Otherwise, fall back to synthesized Google partner from config.
fn resolve_partner<'a>(
    state: &'a IdpState,
    partner_id: Option<&str>,
) -> Option<ResolvedPartner<'a>> {
    if let Some(pid) = partner_id {
        let partner = state.partners.iter().find(|p| p.id == pid && p.enabled)?;
        let acs_url = partner.saml_acs_url.as_deref()?;
        let entity_id = partner.saml_entity_id.as_deref().unwrap_or(acs_url);
        Some(ResolvedPartner {
            _partner_id: &partner.id,
            acs_url,
            audience: entity_id,
            _partner: Some(partner),
        })
    } else {
        // Fall back to Google config
        let google = state.config.idp.google.as_ref()?;
        Some(ResolvedPartner {
            _partner_id: "google",
            acs_url: &google.google_acs_url,
            audience: &google.google_entity_id,
            _partner: None,
        })
    }
}

/// Resolved target for SAML response generation.
struct ResolvedPartner<'a> {
    _partner_id: &'a str,
    acs_url: &'a str,
    audience: &'a str,
    _partner: Option<&'a SsoPartner>,
}

/// Create a portal session and return the Set-Cookie header value.
async fn create_portal_session_cookie(state: &IdpState, user_sourced_id: &str) -> Option<String> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires = now + chrono::Duration::hours(8);
    let session = chalk_core::models::sso::PortalSession {
        id: session_id.clone(),
        user_sourced_id: user_sourced_id.to_string(),
        created_at: now,
        expires_at: expires,
    };

    state.repo.create_portal_session(&session).await.ok()?;

    Some(format!(
        "chalk_portal={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800",
        session_id
    ))
}

fn build_saml_post_response(
    state: &IdpState,
    user_email: &str,
    relay_state: Option<String>,
    request_id: Option<&str>,
    partner_id: Option<&str>,
) -> Option<Response> {
    let resolved = resolve_partner(state, partner_id)?;
    let entity_id = state
        .config
        .chalk
        .public_url
        .as_deref()
        .unwrap_or("https://chalk.local");

    let saml_response = if let (Some(key), Some(cert)) = (&state.signing_key, &state.signing_cert) {
        crate::saml::build_signed_saml_response(
            user_email,
            entity_id,
            resolved.acs_url,
            resolved.audience,
            request_id,
            key,
            cert,
        )
        .unwrap_or_else(|e| {
            tracing::warn!("SAML signing failed, using unsigned: {e}");
            crate::saml::build_saml_response(
                user_email,
                entity_id,
                resolved.acs_url,
                resolved.audience,
                request_id,
            )
        })
    } else {
        crate::saml::build_saml_response(
            user_email,
            entity_id,
            resolved.acs_url,
            resolved.audience,
            request_id,
        )
    };

    let saml_response_b64 = BASE64.encode(saml_response.as_bytes());

    let template = SamlPostBindingTemplate {
        acs_url: resolved.acs_url.to_string(),
        saml_response_b64,
        relay_state,
    };
    Some(Html(template.render().unwrap_or_default()).into_response())
}

/// Build a SAML response and attach the portal session cookie.
async fn build_authenticated_response(
    state: &IdpState,
    user_email: &str,
    user_sourced_id: &str,
    relay_state: Option<String>,
    request_id: Option<&str>,
    partner_id: Option<&str>,
) -> Response {
    // Create portal session cookie
    let cookie = create_portal_session_cookie(state, user_sourced_id).await;

    if let Some(mut response) =
        build_saml_post_response(state, user_email, relay_state, request_id, partner_id)
    {
        if let Some(cookie_val) = cookie {
            if let Ok(hv) = cookie_val.parse() {
                response.headers_mut().insert(SET_COOKIE, hv);
            }
        }
        response
    } else {
        let mut response = Html(format!("Login successful for {}", user_email)).into_response();
        if let Some(cookie_val) = cookie {
            if let Ok(hv) = cookie_val.parse() {
                response.headers_mut().insert(SET_COOKIE, hv);
            }
        }
        response
    }
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
            build_authenticated_response(
                &state,
                email,
                &user.sourced_id,
                form.relay_state,
                form.saml_request_id.as_deref(),
                form.partner_id.as_deref(),
            )
            .await
        }
        Err(e) => render_error(&e.to_string()),
    }
}

async fn login_qr(State(state): State<Arc<IdpState>>, Form(form): Form<QrLoginForm>) -> Response {
    match crate::auth::authenticate_qr_badge(state.repo.as_ref(), &form.badge_token).await {
        Ok(user) => {
            let email = user.email.as_deref().unwrap_or(&user.username);
            build_authenticated_response(
                &state,
                email,
                &user.sourced_id,
                None,
                None,
                form.partner_id.as_deref(),
            )
            .await
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
            build_authenticated_response(
                &state,
                email,
                &user.sourced_id,
                None,
                None,
                form.partner_id.as_deref(),
            )
            .await
        }
        Err(e) => render_error(&e.to_string()),
    }
}

/// IDP-initiated SAML flow: requires a valid portal session.
async fn saml_initiate(
    State(state): State<Arc<IdpState>>,
    Path(partner_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Extract portal session from cookie
    let session_id = match extract_cookie(&headers, "chalk_portal") {
        Some(id) => id,
        None => return render_error("No portal session. Please log in first."),
    };

    // Validate portal session
    let session = match state.repo.get_portal_session(&session_id).await {
        Ok(Some(s)) if s.expires_at > Utc::now() => s,
        Ok(Some(_)) => return render_error("Portal session expired. Please log in again."),
        Ok(None) => return render_error("Invalid portal session. Please log in again."),
        Err(e) => return render_error(&format!("Session lookup failed: {e}")),
    };

    // Look up partner
    let partner = match state
        .partners
        .iter()
        .find(|p| p.id == partner_id && p.enabled)
    {
        Some(p) => p,
        None => return render_error("Unknown or disabled partner"),
    };

    // Load user to get email
    let user = match state.repo.get_user(&session.user_sourced_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return render_error("User not found"),
        Err(e) => return render_error(&format!("User lookup failed: {e}")),
    };

    // Check role access — RoleType serializes to lowercase via serde
    let role_str = format!("{:?}", user.role).to_lowercase();
    if !partner.is_accessible_by_role(&role_str) {
        return render_error("You do not have access to this application");
    }

    let email = user.email.as_deref().unwrap_or(&user.username);
    let entity_id = state
        .config
        .chalk
        .public_url
        .as_deref()
        .unwrap_or("https://chalk.local");

    let acs_url = match partner.saml_acs_url.as_deref() {
        Some(url) => url,
        None => return render_error("Partner has no ACS URL configured"),
    };
    let audience = partner.saml_entity_id.as_deref().unwrap_or(acs_url);

    let saml_response = if let (Some(key), Some(cert)) = (&state.signing_key, &state.signing_cert) {
        crate::saml::build_signed_saml_response(
            email, entity_id, acs_url, audience, None, key, cert,
        )
        .unwrap_or_else(|e| {
            tracing::warn!("SAML signing failed, using unsigned: {e}");
            crate::saml::build_saml_response(email, entity_id, acs_url, audience, None)
        })
    } else {
        crate::saml::build_saml_response(email, entity_id, acs_url, audience, None)
    };

    let saml_response_b64 = BASE64.encode(saml_response.as_bytes());
    let template = SamlPostBindingTemplate {
        acs_url: acs_url.to_string(),
        saml_response_b64,
        relay_state: None,
    };
    Html(template.render().unwrap_or_default()).into_response()
}

/// Extract a cookie value by name from the request headers.
fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            let value = value.strip_prefix('=')?;
            return Some(value.to_string());
        }
    }
    None
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
                admin_password_hash: None,
            },
            sis: SisConfig::default(),
            idp: IdpConfig {
                enabled: true,
                qr_badge_login: true,
                picture_passwords: true,
                saml_cert_path: None,
                saml_key_path: None,
                session_timeout_minutes: 480,
                default_password_pattern: None,
                default_password_roles: vec![],
                google: None,
            },
            google_sync: Default::default(),
            ad_sync: Default::default(),
            agent: Default::default(),
            marketplace: Default::default(),
            sso_partners: Vec::new(),
            webhooks: Vec::new(),
        };
        Arc::new(IdpState {
            repo,
            config,
            partners: Vec::new(),
            signing_key: None,
            signing_cert: None,
        })
    }

    async fn setup_state_with_partners() -> Arc<IdpState> {
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
                admin_password_hash: None,
            },
            sis: SisConfig::default(),
            idp: IdpConfig {
                enabled: true,
                qr_badge_login: true,
                picture_passwords: true,
                saml_cert_path: None,
                saml_key_path: None,
                session_timeout_minutes: 480,
                default_password_pattern: None,
                default_password_roles: vec![],
                google: None,
            },
            google_sync: Default::default(),
            ad_sync: Default::default(),
            agent: Default::default(),
            marketplace: Default::default(),
            sso_partners: Vec::new(),
            webhooks: Vec::new(),
        };
        let now = Utc::now();
        let partners = vec![
            SsoPartner {
                id: "partner-clever".to_string(),
                name: "Clever".to_string(),
                logo_url: None,
                protocol: chalk_core::models::sso::SsoProtocol::Saml,
                enabled: true,
                source: chalk_core::models::sso::SsoPartnerSource::Toml,
                tenant_id: None,
                roles: vec![],
                saml_entity_id: Some("https://clever.com".to_string()),
                saml_acs_url: Some("https://clever.com/saml/consume".to_string()),
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_redirect_uris: vec![],
                created_at: now,
                updated_at: now,
            },
            SsoPartner {
                id: "partner-canvas".to_string(),
                name: "Canvas".to_string(),
                logo_url: None,
                protocol: chalk_core::models::sso::SsoProtocol::Saml,
                enabled: true,
                source: chalk_core::models::sso::SsoPartnerSource::Toml,
                tenant_id: None,
                roles: vec!["teacher".to_string()],
                saml_entity_id: Some("https://canvas.example.com".to_string()),
                saml_acs_url: Some("https://canvas.example.com/saml/consume".to_string()),
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_redirect_uris: vec![],
                created_at: now,
                updated_at: now,
            },
        ];
        Arc::new(IdpState {
            repo,
            config,
            partners,
            signing_key: None,
            signing_cert: None,
        })
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

    #[tokio::test]
    async fn saml_sso_unknown_issuer_returns_error() {
        let state = setup_state_with_partners().await;
        let app = router(state);

        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                             ID="_req_test"
                             Version="2.0">
          <saml:Issuer>https://unknown.com</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let encoded = BASE64.encode(xml.as_bytes());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/saml/sso?SAMLRequest={}", encoded))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Unknown service provider"));
    }

    #[tokio::test]
    async fn saml_sso_known_issuer_shows_login() {
        let state = setup_state_with_partners().await;
        let app = router(state);

        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                             ID="_req_clever"
                             Version="2.0">
          <saml:Issuer>https://clever.com</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let encoded = BASE64.encode(xml.as_bytes());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/saml/sso?SAMLRequest={}", encoded))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn saml_initiate_no_session_returns_error() {
        let state = setup_state_with_partners().await;
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/saml/initiate/partner-clever")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("No portal session"));
    }

    #[tokio::test]
    async fn saml_initiate_invalid_session_returns_error() {
        let state = setup_state_with_partners().await;
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/saml/initiate/partner-clever")
                    .header("cookie", "chalk_portal=nonexistent-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Invalid portal session"));
    }

    #[tokio::test]
    async fn extract_cookie_parses_correctly() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "other=val; chalk_portal=session-123; more=stuff"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_cookie(&headers, "chalk_portal"),
            Some("session-123".to_string())
        );
    }

    #[tokio::test]
    async fn extract_cookie_missing_returns_none() {
        let headers = axum::http::HeaderMap::new();
        assert_eq!(extract_cookie(&headers, "chalk_portal"), None);
    }

    #[tokio::test]
    async fn resolve_partner_finds_by_id() {
        let state = setup_state_with_partners().await;
        let resolved = resolve_partner(&state, Some("partner-clever"));
        assert!(resolved.is_some());
        let r = resolved.unwrap();
        assert_eq!(r.acs_url, "https://clever.com/saml/consume");
    }

    #[tokio::test]
    async fn resolve_partner_returns_none_for_unknown() {
        let state = setup_state_with_partners().await;
        let resolved = resolve_partner(&state, Some("partner-unknown"));
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn resolve_partner_falls_back_to_google() {
        let state = setup_state().await;
        // No google config, so should return None
        let resolved = resolve_partner(&state, None);
        assert!(resolved.is_none());
    }
}
