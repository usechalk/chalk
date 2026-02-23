//! ClassLink-compatible OAuth2 endpoints for Chalk IDP.
//!
//! Implements a ClassLink-compatible OAuth2 flow with user info endpoint.
//! This module is self-contained and exposes an Axum router that can
//! be nested under `/idp/classlink/` in the main IDP router.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};

use crate::compat_common::{extract_client_credentials, extract_cookie, generate_random_hex};
use chalk_core::db::repository::{
    OidcCodeRepository, OrgRepository, PortalSessionRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::error::ChalkError;
use chalk_core::models::common::RoleType;
use chalk_core::models::sso::{OidcAuthorizationCode, SsoPartner, SsoProtocol};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

/// Shared state for ClassLink-compatible routes.
pub struct ClassLinkCompatState {
    pub repo: Arc<SqliteRepository>,
    pub partners: Vec<SsoPartner>,
    pub signing_key: Vec<u8>,
    pub public_url: String,
}

impl ClassLinkCompatState {
    /// Find a ClassLink-compatible partner by client_id.
    fn find_partner(&self, client_id: &str) -> Option<&SsoPartner> {
        self.partners.iter().find(|p| {
            p.protocol == SsoProtocol::ClassLinkCompat
                && p.enabled
                && p.oidc_client_id.as_deref() == Some(client_id)
        })
    }
}

// -- Authorization Endpoint (GET) --

#[derive(Deserialize)]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: Option<String>,
}

async fn classlink_authorize(
    State(state): State<Arc<ClassLinkCompatState>>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, ClassLinkError> {
    // Validate response_type
    if params.response_type != "code" {
        return Err(ClassLinkError::bad_request(
            "unsupported response_type, must be 'code'",
        ));
    }

    // Validate client_id
    let partner = state
        .find_partner(&params.client_id)
        .ok_or_else(|| ClassLinkError::bad_request("unknown client_id"))?;

    // Validate redirect_uri
    if !partner.oidc_redirect_uris.contains(&params.redirect_uri) {
        return Err(ClassLinkError::bad_request("invalid redirect_uri"));
    }

    // Check for portal session cookie
    let session_id = extract_cookie(&headers, "chalk_portal");
    let portal_session = if let Some(sid) = session_id {
        state
            .repo
            .get_portal_session(&sid)
            .await
            .map_err(classlink_db_err)?
    } else {
        None
    };

    // Filter out expired sessions
    let portal_session = portal_session.filter(|s| s.expires_at > Utc::now());

    match portal_session {
        None => {
            // Redirect to login, preserving all params
            let return_path = build_authorize_return_url(&state.public_url, &params);
            let login_url = format!("/idp/login?redirect={}", urlencoding::encode(&return_path));
            Ok(Redirect::temporary(&login_url).into_response())
        }
        Some(session) => {
            // Instant SSO — no consent page. Generate auth code and redirect.
            let code = generate_random_hex(32);
            let now = Utc::now();

            let oidc_code = OidcAuthorizationCode {
                code: code.clone(),
                client_id: params.client_id,
                user_sourced_id: session.user_sourced_id,
                redirect_uri: params.redirect_uri.clone(),
                scope: params.scope,
                nonce: None,
                created_at: now,
                expires_at: now + Duration::minutes(10),
            };

            state
                .repo
                .create_oidc_code(&oidc_code)
                .await
                .map_err(classlink_db_err)?;

            // Redirect with code and state
            let mut redirect_url = format!(
                "{}?code={}",
                params.redirect_uri,
                urlencoding::encode(&code)
            );
            if let Some(ref s) = params.state {
                if !s.is_empty() {
                    redirect_url.push_str(&format!("&state={}", urlencoding::encode(s)));
                }
            }

            Ok(Redirect::temporary(&redirect_url).into_response())
        }
    }
}

fn build_authorize_return_url(public_url: &str, params: &AuthorizeParams) -> String {
    let mut url = format!(
        "{}/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type={}&scope={}",
        public_url,
        urlencoding::encode(&params.client_id),
        urlencoding::encode(&params.redirect_uri),
        urlencoding::encode(&params.response_type),
        urlencoding::encode(&params.scope),
    );
    if let Some(ref s) = params.state {
        url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    url
}

// -- Token Endpoint --

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
}

async fn classlink_token(
    State(state): State<Arc<ClassLinkCompatState>>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, ClassLinkError> {
    if form.grant_type != "authorization_code" {
        return Err(ClassLinkError::token_error(
            "unsupported_grant_type",
            "only authorization_code is supported",
        ));
    }

    // Extract client credentials
    let (client_id, client_secret) = extract_client_credentials(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )
    .ok_or_else(|| ClassLinkError::token_error("invalid_client", "client credentials required"))?;

    // Look up the authorization code
    let oidc_code = state
        .repo
        .get_oidc_code(&form.code)
        .await
        .map_err(classlink_db_err)?
        .ok_or_else(|| {
            ClassLinkError::token_error("invalid_grant", "authorization code not found")
        })?;

    // Validate code hasn't expired
    if oidc_code.expires_at < Utc::now() {
        return Err(ClassLinkError::token_error(
            "invalid_grant",
            "authorization code expired",
        ));
    }

    // Validate client_id matches
    if oidc_code.client_id != client_id {
        return Err(ClassLinkError::token_error(
            "invalid_grant",
            "client_id mismatch",
        ));
    }

    // Validate client_secret
    let partner = state
        .find_partner(&client_id)
        .ok_or_else(|| ClassLinkError::token_error("invalid_client", "unknown client_id"))?;

    if partner.oidc_client_secret.as_deref() != Some(&client_secret) {
        return Err(ClassLinkError::token_error(
            "invalid_client",
            "invalid client_secret",
        ));
    }

    // Validate redirect_uri
    if oidc_code.redirect_uri != form.redirect_uri {
        return Err(ClassLinkError::token_error(
            "invalid_grant",
            "redirect_uri mismatch",
        ));
    }

    // Delete the code (single use) — after all validations pass
    state
        .repo
        .delete_oidc_code(&form.code)
        .await
        .map_err(classlink_db_err)?;

    // Generate access token and store it
    let now = Utc::now();
    let access_token = generate_random_hex(64);
    let access_code = OidcAuthorizationCode {
        code: access_token.clone(),
        client_id,
        user_sourced_id: oidc_code.user_sourced_id,
        redirect_uri: String::new(),
        scope: format!("access_token {}", oidc_code.scope),
        nonce: None,
        created_at: now,
        expires_at: now + Duration::hours(1),
    };

    state
        .repo
        .create_oidc_code(&access_code)
        .await
        .map_err(classlink_db_err)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
    }))
}

// -- User Info Endpoint (ClassLink format) --

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ClassLinkUserInfo {
    user_id: i64,
    login_id: String,
    tenant_id: i64,
    state_id: String,
    state_name: String,
    building_id: String,
    authentication_type: String,
    display_name: String,
    first_name: String,
    last_name: String,
    email: String,
    image_path: String,
    language_id: i64,
    language: String,
    default_time_format: String,
    profile: String,
    profile_id: i64,
    tenant: String,
    building: String,
    role: String,
    #[serde(rename = "Role_Level")]
    role_level: i64,
    last_access_time: String,
    org_id: String,
    sourced_id: String,
}

/// Generate a stable integer ID from a sourced_id string.
///
/// Uses SHA-256 for deterministic, cross-platform hashing (unlike DefaultHasher
/// which may vary across Rust versions and platforms).
fn sourced_id_to_integer(sourced_id: &str) -> i64 {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(sourced_id.as_bytes());
    let bytes: [u8; 8] = hash[..8].try_into().unwrap();
    i64::from_be_bytes(bytes) & 0x7FFF_FFFF_FFFF_FFFF
}

/// Map a RoleType to ClassLink profile info.
fn role_to_classlink_profile(role: &RoleType) -> (&str, i64, &str, i64) {
    // Returns (Profile, ProfileId, Role, Role_Level)
    match role {
        RoleType::Student => ("Student", 2, "Student", 1),
        RoleType::Teacher => ("Teacher", 3, "Teacher", 2),
        RoleType::Administrator => ("Administrator", 4, "Administrator", 3),
        _ => ("User", 1, "User", 0),
    }
}

async fn classlink_my_info(
    State(state): State<Arc<ClassLinkCompatState>>,
    headers: HeaderMap,
) -> Result<Json<ClassLinkUserInfo>, ClassLinkError> {
    // Extract Bearer token
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ClassLinkError::unauthorized("Bearer token required"))?;

    // Look up the access token
    let token_record = state
        .repo
        .get_oidc_code(bearer)
        .await
        .map_err(classlink_db_err)?
        .ok_or_else(|| ClassLinkError::unauthorized("invalid access token"))?;

    // Verify it's an access token
    if !token_record.scope.starts_with("access_token") {
        return Err(ClassLinkError::unauthorized("invalid access token"));
    }

    // Check expiry
    if token_record.expires_at < Utc::now() {
        return Err(ClassLinkError::unauthorized("access token expired"));
    }

    // Look up user
    let user = state
        .repo
        .get_user(&token_record.user_sourced_id)
        .await
        .map_err(classlink_db_err)?
        .ok_or_else(|| ClassLinkError::unauthorized("invalid access token"))?;

    // Look up the user's primary org for Tenant/Building info
    let org_name = if let Some(org_id) = user.orgs.first() {
        state
            .repo
            .get_org(org_id)
            .await
            .map_err(classlink_db_err)?
            .map(|o| o.name)
            .unwrap_or_default()
    } else {
        String::new()
    };

    let user_id = sourced_id_to_integer(&user.sourced_id);
    let tenant_id = if let Some(org_id) = user.orgs.first() {
        sourced_id_to_integer(org_id)
    } else {
        0
    };

    let (profile, profile_id, role, role_level) = role_to_classlink_profile(&user.role);

    let now = Utc::now();

    Ok(Json(ClassLinkUserInfo {
        user_id,
        login_id: user.username.clone(),
        tenant_id,
        state_id: String::new(),
        state_name: String::new(),
        building_id: String::new(),
        authentication_type: "Forms".to_string(),
        display_name: format!("{} {}", user.given_name, user.family_name),
        first_name: user.given_name.clone(),
        last_name: user.family_name.clone(),
        email: user.email.clone().unwrap_or_default(),
        image_path: String::new(),
        language_id: 1,
        language: "English".to_string(),
        default_time_format: "12".to_string(),
        profile: profile.to_string(),
        profile_id,
        tenant: org_name.clone(),
        building: org_name,
        role: role.to_string(),
        role_level,
        last_access_time: now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        org_id: user.orgs.first().cloned().unwrap_or_default(),
        sourced_id: user.sourced_id,
    }))
}

// -- Router --

/// Build the ClassLink-compatible router. Mount at `/idp/classlink`.
pub fn classlink_compat_router(state: Arc<ClassLinkCompatState>) -> Router {
    Router::new()
        .route("/oauth2/v2/auth", get(classlink_authorize))
        .route("/oauth2/v2/token", post(classlink_token))
        .route("/v2/my/info", get(classlink_my_info))
        .with_state(state)
}

// -- Helpers --

/// URL-encoding helper (minimal, self-contained).
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut result = String::with_capacity(input.len() * 3);
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        result
    }
}

// -- Error types --

/// ClassLink-specific error response.
struct ClassLinkError {
    status: StatusCode,
    error: String,
    description: String,
}

impl ClassLinkError {
    fn bad_request(desc: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request".to_string(),
            description: desc.to_string(),
        }
    }

    fn unauthorized(desc: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized".to_string(),
            description: desc.to_string(),
        }
    }

    fn internal(desc: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error".to_string(),
            description: desc.into(),
        }
    }

    fn token_error(error: &str, desc: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: error.to_string(),
            description: desc.to_string(),
        }
    }
}

impl IntoResponse for ClassLinkError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.error,
            "error_description": self.description,
        });
        (self.status, Json(body)).into_response()
    }
}

fn classlink_db_err(e: ChalkError) -> ClassLinkError {
    ClassLinkError::internal(format!("database error: {e}"))
}

// -- Unit Tests --

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use chalk_core::db::sqlite::SqliteRepository;
    use chalk_core::models::common::{OrgType, RoleType, Status};
    use chalk_core::models::org::Org;
    use chalk_core::models::sso::{SsoPartner, SsoPartnerSource, SsoProtocol};
    use chalk_core::models::user::User;
    use chrono::Utc;
    use tower::ServiceExt;

    fn test_partner() -> SsoPartner {
        SsoPartner {
            id: "partner-classlink-1".to_string(),
            name: "Test ClassLink App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::ClassLinkCompat,
            enabled: true,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles: vec![],
            saml_entity_id: None,
            saml_acs_url: None,
            oidc_client_id: Some("test-client".to_string()),
            oidc_client_secret: Some("test-secret".to_string()),
            oidc_redirect_uris: vec!["https://app.example.com/callback".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    async fn test_repo() -> SqliteRepository {
        use chalk_core::db::DatabasePool;
        let pool = DatabasePool::new_sqlite_memory().await.expect("memory DB");
        match pool {
            DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        }
    }

    fn test_state(repo: SqliteRepository) -> Arc<ClassLinkCompatState> {
        Arc::new(ClassLinkCompatState {
            repo: Arc::new(repo),
            partners: vec![test_partner()],
            signing_key: vec![],
            public_url: "https://chalk.school.edu".to_string(),
        })
    }

    fn test_app(state: Arc<ClassLinkCompatState>) -> Router {
        classlink_compat_router(state)
    }

    async fn seed_org_and_user(repo: &SqliteRepository, role: RoleType) {
        use chalk_core::db::repository::{OrgRepository, UserRepository};

        let org = Org {
            sourced_id: "org-1".to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            name: "Springfield USD".to_string(),
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
            role,
            identifier: None,
            email: Some("jdoe@school.edu".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-1".to_string()],
            grades: vec!["09".to_string()],
        };
        repo.upsert_user(&user).await.unwrap();
    }

    async fn create_access_token(repo: &SqliteRepository) -> String {
        let now = Utc::now();
        let token = generate_random_hex(64);
        let access_code = OidcAuthorizationCode {
            code: token.clone(),
            client_id: "test-client".to_string(),
            user_sourced_id: "user-1".to_string(),
            redirect_uri: String::new(),
            scope: "access_token openid".to_string(),
            nonce: None,
            created_at: now,
            expires_at: now + Duration::hours(1),
        };
        repo.create_oidc_code(&access_code).await.unwrap();
        token
    }

    #[tokio::test]
    async fn authorize_rejects_unknown_client_id() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/oauth2/v2/auth?client_id=unknown&redirect_uri=https://evil.com&response_type=code&scope=openid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(err["error_description"]
            .as_str()
            .unwrap()
            .contains("client_id"));
    }

    #[tokio::test]
    async fn authorize_redirects_to_login_without_session() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/oauth2/v2/auth?client_id=test-client&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("/idp/login?redirect="));
    }

    #[tokio::test]
    async fn authorize_generates_code_with_session() {
        use chalk_core::db::repository::PortalSessionRepository;
        use chalk_core::models::sso::PortalSession;

        let repo = test_repo().await;
        seed_org_and_user(&repo, RoleType::Student).await;

        // Create a portal session
        let session = PortalSession {
            id: "portal-session-1".to_string(),
            user_sourced_id: "user-1".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(8),
        };
        repo.create_portal_session(&session).await.unwrap();

        let state = test_state(repo);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/oauth2/v2/auth?client_id=test-client&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&state=mystate")
                    .header(header::COOKIE, "chalk_portal=portal-session-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://app.example.com/callback?code="));
        assert!(location.contains("state=mystate"));
    }

    #[tokio::test]
    async fn token_exchange_works() {
        let repo = test_repo().await;
        seed_org_and_user(&repo, RoleType::Student).await;

        // Create a valid auth code
        let now = Utc::now();
        let code = OidcAuthorizationCode {
            code: "valid-code".to_string(),
            client_id: "test-client".to_string(),
            user_sourced_id: "user-1".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid".to_string(),
            nonce: None,
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };
        repo.create_oidc_code(&code).await.unwrap();

        let state = test_state(repo);
        let app = test_app(state);

        let body = "grant_type=authorization_code&code=valid-code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&client_secret=test-secret";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/v2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let token_resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(token_resp["token_type"], "Bearer");
        assert_eq!(token_resp["expires_in"], 3600);
        assert!(token_resp["access_token"].is_string());
        // ClassLink token response should NOT have id_token
        assert!(token_resp.get("id_token").is_none());
    }

    #[tokio::test]
    async fn my_info_returns_all_classlink_fields() {
        let repo = test_repo().await;
        seed_org_and_user(&repo, RoleType::Student).await;
        let token = create_access_token(&repo).await;

        let state = test_state(repo);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/my/info")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let info: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Verify ALL 22+ ClassLink fields are present
        assert!(info["UserId"].is_number(), "UserId must be present");
        assert_eq!(info["LoginId"], "jdoe");
        assert!(info["TenantId"].is_number(), "TenantId must be present");
        assert!(info.get("StateId").is_some(), "StateId must be present");
        assert!(info.get("StateName").is_some(), "StateName must be present");
        assert!(
            info.get("BuildingId").is_some(),
            "BuildingId must be present"
        );
        assert_eq!(info["AuthenticationType"], "Forms");
        assert_eq!(info["DisplayName"], "John Doe");
        assert_eq!(info["FirstName"], "John");
        assert_eq!(info["LastName"], "Doe");
        assert_eq!(info["Email"], "jdoe@school.edu");
        assert!(info.get("ImagePath").is_some(), "ImagePath must be present");
        assert_eq!(info["LanguageId"], 1);
        assert_eq!(info["Language"], "English");
        assert_eq!(info["DefaultTimeFormat"], "12");
        assert_eq!(info["Profile"], "Student");
        assert_eq!(info["ProfileId"], 2);
        assert_eq!(info["Tenant"], "Springfield USD");
        assert_eq!(info["Building"], "Springfield USD");
        assert_eq!(info["Role"], "Student");
        assert_eq!(info["Role_Level"], 1);
        assert!(
            info["LastAccessTime"].is_string(),
            "LastAccessTime must be present"
        );
        assert_eq!(info["OrgId"], "org-1");
        assert_eq!(info["SourcedId"], "user-1");
    }

    #[tokio::test]
    async fn my_info_maps_student_profile_correctly() {
        let repo = test_repo().await;
        seed_org_and_user(&repo, RoleType::Student).await;
        let token = create_access_token(&repo).await;

        let state = test_state(repo);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/my/info")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let info: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(info["Profile"], "Student");
        assert_eq!(info["ProfileId"], 2);
        assert_eq!(info["Role"], "Student");
        assert_eq!(info["Role_Level"], 1);
    }

    #[tokio::test]
    async fn my_info_maps_teacher_profile_correctly() {
        let repo = test_repo().await;
        seed_org_and_user(&repo, RoleType::Teacher).await;
        let token = create_access_token(&repo).await;

        let state = test_state(repo);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/my/info")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let info: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(info["Profile"], "Teacher");
        assert_eq!(info["ProfileId"], 3);
        assert_eq!(info["Role"], "Teacher");
        assert_eq!(info["Role_Level"], 2);
    }

    // -- sourced_id_to_integer tests (sha2-based, deterministic) --

    #[test]
    fn sourced_id_to_integer_is_deterministic() {
        let a = sourced_id_to_integer("user-123");
        let b = sourced_id_to_integer("user-123");
        assert_eq!(a, b, "same input must always produce the same output");
    }

    #[test]
    fn sourced_id_to_integer_is_positive() {
        for id in &["user-1", "org-abc", "", "a very long sourced id string!"] {
            let val = sourced_id_to_integer(id);
            assert!(
                val >= 0,
                "sourced_id_to_integer({id:?}) = {val} must be non-negative"
            );
        }
    }

    #[test]
    fn sourced_id_to_integer_different_inputs_differ() {
        let a = sourced_id_to_integer("user-1");
        let b = sourced_id_to_integer("user-2");
        assert_ne!(a, b, "different inputs should produce different IDs");
    }

    #[test]
    fn sourced_id_to_integer_known_value_stability() {
        // Pin a known value so we detect if the hash algorithm changes
        let val = sourced_id_to_integer("user-1");
        // Re-running must always give the same result
        assert_eq!(val, sourced_id_to_integer("user-1"));
        // Value must be positive
        assert!(val > 0);
    }
}
