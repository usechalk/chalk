//! Student/teacher launch portal — a standalone page where authenticated users
//! see their assigned SSO apps as tiles and can click to launch them.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, State},
    http::header::SET_COOKIE,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chalk_core::db::repository::{PortalSessionRepository, SsoPartnerRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::models::sso::{SsoPartner, SsoProtocol};
use chrono::Utc;

// -- Templates --

#[derive(Template)]
#[template(path = "portal.html")]
struct PortalTemplate {
    user_display_name: String,
    user_role: String,
    partners: Vec<SsoPartner>,
}

#[derive(Template)]
#[template(path = "saml_post_binding.html")]
struct SamlPostBindingTemplate {
    acs_url: String,
    saml_response_b64: String,
    relay_state: Option<String>,
}

// -- Router --

/// Build the portal router. Mount at `/portal`.
pub fn portal_router(state: Arc<crate::routes::IdpState>) -> Router {
    Router::new()
        .route("/", get(portal_home))
        .route("/launch/:partner_id", get(portal_launch))
        .route("/logout", post(portal_logout))
        .with_state(state)
}

// -- Cookie helper --

/// Extract a cookie value by name from the request headers.
fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Validate the portal session cookie and return the session.
/// On failure, returns a redirect to the login page.
async fn validate_portal_session(
    repo: &SqliteRepository,
    headers: &axum::http::HeaderMap,
) -> Result<chalk_core::models::sso::PortalSession, Response> {
    let session_id = extract_cookie(headers, "chalk_portal")
        .ok_or_else(|| Redirect::temporary("/idp/login?redirect=/portal").into_response())?;

    let session = repo
        .get_portal_session(&session_id)
        .await
        .map_err(|_| Redirect::temporary("/idp/login?redirect=/portal").into_response())?
        .ok_or_else(|| Redirect::temporary("/idp/login?redirect=/portal").into_response())?;

    if session.expires_at <= Utc::now() {
        return Err(Redirect::temporary("/idp/login?redirect=/portal").into_response());
    }

    Ok(session)
}

// -- Handlers --

async fn portal_home(
    State(state): State<Arc<crate::routes::IdpState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let session = match validate_portal_session(&state.repo, &headers).await {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    let user = match state.repo.get_user(&session.user_sourced_id).await {
        Ok(Some(u)) => u,
        _ => return Redirect::temporary("/idp/login?redirect=/portal").into_response(),
    };

    let role_str = format!("{:?}", user.role).to_lowercase();

    let partners: Vec<SsoPartner> = state
        .repo
        .list_sso_partners_for_role(&role_str)
        .await
        .unwrap_or_default();

    let template = PortalTemplate {
        user_display_name: format!("{} {}", user.given_name, user.family_name),
        user_role: role_str,
        partners,
    };

    Html(template.render().unwrap_or_default()).into_response()
}

async fn portal_launch(
    State(state): State<Arc<crate::routes::IdpState>>,
    Path(partner_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let session = match validate_portal_session(&state.repo, &headers).await {
        Ok(s) => s,
        Err(redirect) => return redirect,
    };

    let user = match state.repo.get_user(&session.user_sourced_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_html("User not found"),
        Err(e) => return error_html(&format!("User lookup failed: {e}")),
    };

    // Look up the partner from the database
    let partner = match state.repo.get_sso_partner(&partner_id).await {
        Ok(Some(p)) if p.enabled => p,
        Ok(Some(_)) => return error_html("This application is currently disabled"),
        Ok(None) => return error_html("Application not found"),
        Err(e) => return error_html(&format!("Partner lookup failed: {e}")),
    };

    // Check role access
    let role_str = format!("{:?}", user.role).to_lowercase();
    if !partner.is_accessible_by_role(&role_str) {
        return error_html("You do not have access to this application");
    }

    match partner.protocol {
        SsoProtocol::Saml => launch_saml(&state, &user, &partner),
        SsoProtocol::Oidc => launch_oidc(&state, &partner),
    }
}

fn launch_saml(
    state: &crate::routes::IdpState,
    user: &chalk_core::models::user::User,
    partner: &SsoPartner,
) -> Response {
    let entity_id = state
        .config
        .chalk
        .public_url
        .as_deref()
        .unwrap_or("https://chalk.local");

    let acs_url = match partner.saml_acs_url.as_deref() {
        Some(url) => url,
        None => return error_html("Partner has no ACS URL configured"),
    };
    let audience = partner.saml_entity_id.as_deref().unwrap_or(acs_url);
    let email = user.email.as_deref().unwrap_or(&user.username);

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

fn launch_oidc(state: &crate::routes::IdpState, partner: &SsoPartner) -> Response {
    let base_url = state
        .config
        .chalk
        .public_url
        .as_deref()
        .unwrap_or("https://chalk.local");

    let client_id = match partner.oidc_client_id.as_deref() {
        Some(id) => id,
        None => return error_html("Partner has no OIDC client ID configured"),
    };

    let redirect_uri = match partner.oidc_redirect_uris.first() {
        Some(uri) => uri,
        None => return error_html("Partner has no OIDC redirect URI configured"),
    };

    let authorize_url = format!(
        "{}/idp/oidc/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid%20profile%20email",
        base_url,
        client_id,
        redirect_uri,
    );

    Redirect::temporary(&authorize_url).into_response()
}

async fn portal_logout(
    State(state): State<Arc<crate::routes::IdpState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Delete the portal session from the database if present
    if let Some(session_id) = extract_cookie(&headers, "chalk_portal") {
        let _ = state.repo.delete_portal_session(&session_id).await;
    }

    // Clear the cookie and redirect to login
    let clear_cookie = "chalk_portal=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
    let mut response = Redirect::temporary("/idp/login").into_response();
    if let Ok(hv) = clear_cookie.parse() {
        response.headers_mut().insert(SET_COOKIE, hv);
    }
    response
}

fn error_html(message: &str) -> Response {
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Error</title>
        <style>body{{font-family:sans-serif;max-width:500px;margin:80px auto;text-align:center;}}
        .error{{background:#fef2f2;border:1px solid #fecaca;padding:24px;border-radius:8px;color:#991b1b;}}
        a{{color:#0d9488;margin-top:16px;display:inline-block;}}</style></head>
        <body><div class="error"><h2>Error</h2><p>{}</p></div>
        <a href="/portal">Back to Portal</a></body></html>"#,
        message
    ))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chalk_core::config::{ChalkConfig, ChalkSection, DatabaseConfig, IdpConfig, SisConfig};
    use chalk_core::db::repository::OrgRepository;
    use chalk_core::db::DatabasePool;
    use chalk_core::models::common::{OrgType, RoleType, Status};
    use chalk_core::models::org::Org;
    use chalk_core::models::sso::{PortalSession, SsoPartnerSource};
    use chalk_core::models::user::User;
    use tower::ServiceExt;

    async fn test_repo() -> SqliteRepository {
        let pool = DatabasePool::new_sqlite_memory().await.expect("memory DB");
        match pool {
            DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        }
    }

    fn test_config() -> ChalkConfig {
        ChalkConfig {
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
                qr_badge_login: false,
                picture_passwords: false,
                saml_cert_path: None,
                saml_key_path: None,
                session_timeout_minutes: 480,
                default_password_pattern: None,
                default_password_roles: vec![],
                google: None,
            },
            google_sync: Default::default(),
            agent: Default::default(),
            marketplace: Default::default(),
            sso_partners: Vec::new(),
            webhooks: Vec::new(),
        }
    }

    fn test_state(repo: SqliteRepository) -> Arc<crate::routes::IdpState> {
        Arc::new(crate::routes::IdpState {
            repo: Arc::new(repo),
            config: test_config(),
            partners: Vec::new(),
            signing_key: None,
            signing_cert: None,
        })
    }

    fn test_app(state: Arc<crate::routes::IdpState>) -> Router {
        portal_router(state)
    }

    async fn insert_test_user(repo: &SqliteRepository) -> User {
        let org = Org {
            sourced_id: "org-1".to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            name: "Test School".to_string(),
            org_type: OrgType::School,
            identifier: None,
            parent: None,
            children: vec![],
        };
        repo.upsert_org(&org).await.unwrap();

        let user = User {
            sourced_id: "user-1".to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jdoe@school.edu".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-1".to_string()],
            grades: vec!["09".to_string()],
        };
        repo.upsert_user(&user).await.unwrap();
        user
    }

    async fn insert_portal_session(repo: &SqliteRepository, user_sourced_id: &str) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = PortalSession {
            id: session_id.clone(),
            user_sourced_id: user_sourced_id.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
        };
        repo.create_portal_session(&session).await.unwrap();
        session_id
    }

    async fn insert_test_partner(repo: &SqliteRepository) -> SsoPartner {
        let partner = SsoPartner {
            id: "partner-test".to_string(),
            name: "Test App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::Saml,
            enabled: true,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles: vec![],
            saml_entity_id: Some("https://test-app.example.com".to_string()),
            saml_acs_url: Some("https://test-app.example.com/saml/consume".to_string()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uris: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        repo.upsert_sso_partner(&partner).await.unwrap();
        partner
    }

    #[tokio::test]
    async fn portal_home_redirects_without_session() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("/idp/login"));
    }

    #[tokio::test]
    async fn portal_home_redirects_with_invalid_session() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", "chalk_portal=nonexistent-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[tokio::test]
    async fn portal_home_renders_with_valid_session() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;
        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("John Doe"));
        assert!(body_str.contains("student"));
    }

    #[tokio::test]
    async fn portal_home_shows_empty_state_when_no_partners() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;
        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("No apps configured yet"));
    }

    #[tokio::test]
    async fn portal_home_shows_partner_tiles() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;
        insert_test_partner(&repo).await;
        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("Test App"));
        assert!(body_str.contains("/portal/launch/partner-test"));
    }

    #[tokio::test]
    async fn portal_launch_returns_error_for_invalid_partner() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;
        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/launch/nonexistent")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("Application not found"));
    }

    #[tokio::test]
    async fn portal_launch_saml_partner_returns_post_form() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;
        insert_test_partner(&repo).await;
        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/launch/partner-test")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("SAMLResponse"));
        assert!(body_str.contains("https://test-app.example.com/saml/consume"));
    }

    #[tokio::test]
    async fn portal_launch_denies_wrong_role() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;

        // Create a partner that only allows teachers
        let partner = SsoPartner {
            id: "partner-teachers-only".to_string(),
            name: "Teacher App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::Saml,
            enabled: true,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles: vec!["teacher".to_string()],
            saml_entity_id: Some("https://teacher-app.example.com".to_string()),
            saml_acs_url: Some("https://teacher-app.example.com/saml/consume".to_string()),
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uris: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        repo.upsert_sso_partner(&partner).await.unwrap();

        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/launch/partner-teachers-only")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("do not have access"));
    }

    #[tokio::test]
    async fn portal_logout_clears_cookie_and_redirects() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header("cookie", "chalk_portal=some-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("/idp/login"));
        let set_cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("chalk_portal="));
        assert!(set_cookie.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn portal_launch_redirects_without_session() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/launch/partner-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
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
    async fn portal_launch_oidc_partner_redirects() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;

        let partner = SsoPartner {
            id: "partner-oidc".to_string(),
            name: "OIDC App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::Oidc,
            enabled: true,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles: vec![],
            saml_entity_id: None,
            saml_acs_url: None,
            oidc_client_id: Some("oidc-client-1".to_string()),
            oidc_client_secret: Some("secret".to_string()),
            oidc_redirect_uris: vec!["https://oidc-app.example.com/callback".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        repo.upsert_sso_partner(&partner).await.unwrap();

        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/launch/partner-oidc")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("/idp/oidc/authorize"));
        assert!(location.contains("oidc-client-1"));
    }
}
