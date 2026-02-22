//! OIDC Authorization Code flow provider for Chalk IDP.
//!
//! Implements OpenID Connect 1.0 with Authorization Code flow.
//! This module is self-contained and exposes an Axum router that can
//! be nested under `/idp/oidc/` in the main IDP router.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chalk_core::db::repository::{OidcCodeRepository, PortalSessionRepository, UserRepository};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::error::ChalkError;
use chalk_core::models::sso::{OidcAuthorizationCode, SsoPartner, SsoProtocol};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};

/// Shared state for OIDC routes.
pub struct OidcState {
    pub repo: Arc<SqliteRepository>,
    pub partners: Vec<SsoPartner>,
    pub signing_key: Vec<u8>,
    pub public_url: String,
}

impl OidcState {
    /// Find an OIDC partner by client_id.
    fn find_partner(&self, client_id: &str) -> Option<&SsoPartner> {
        self.partners.iter().find(|p| {
            p.protocol == SsoProtocol::Oidc
                && p.enabled
                && p.oidc_client_id.as_deref() == Some(client_id)
        })
    }
}

// -- Discovery Document --

#[derive(Serialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
}

async fn oidc_discovery(State(state): State<Arc<OidcState>>) -> Json<DiscoveryDocument> {
    let base = &state.public_url;
    Json(DiscoveryDocument {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/idp/oidc/authorize"),
        token_endpoint: format!("{base}/idp/oidc/token"),
        userinfo_endpoint: format!("{base}/idp/oidc/userinfo"),
        jwks_uri: format!("{base}/idp/oidc/jwks"),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        grant_types_supported: vec!["authorization_code".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post".to_string(),
            "client_secret_basic".to_string(),
        ],
    })
}

// -- JWKS Endpoint --

#[derive(Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    #[serde(rename = "use")]
    use_: String,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

async fn oidc_jwks(State(state): State<Arc<OidcState>>) -> Result<Json<JwkSet>, OidcError> {
    let rsa_key = rsa::RsaPrivateKey::from_pkcs1_pem(
        std::str::from_utf8(&state.signing_key)
            .map_err(|e| OidcError::internal(format!("invalid PEM encoding: {e}")))?,
    )
    .map_err(|e| OidcError::internal(format!("invalid RSA private key: {e}")))?;

    let public_key = rsa_key.to_public_key();
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();

    let jwk = Jwk {
        kty: "RSA".to_string(),
        use_: "sig".to_string(),
        alg: "RS256".to_string(),
        kid: "chalk-oidc-1".to_string(),
        n: URL_SAFE_NO_PAD.encode(n_bytes),
        e: URL_SAFE_NO_PAD.encode(e_bytes),
    };

    Ok(Json(JwkSet { keys: vec![jwk] }))
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
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Template)]
#[template(path = "oidc_consent.html")]
struct ConsentTemplate {
    app_name: String,
    scopes: Vec<String>,
    user_name: String,
    user_email: String,
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: String,
    nonce: String,
}

async fn oidc_authorize(
    State(state): State<Arc<OidcState>>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, OidcError> {
    // Validate response_type
    if params.response_type != "code" {
        return Err(OidcError::bad_request("unsupported response_type, must be 'code'"));
    }

    // Validate client_id
    let partner = state
        .find_partner(&params.client_id)
        .ok_or_else(|| OidcError::bad_request("unknown client_id"))?;

    // Validate redirect_uri
    if !partner.oidc_redirect_uris.contains(&params.redirect_uri) {
        return Err(OidcError::bad_request("invalid redirect_uri"));
    }

    // Check for portal session cookie
    let session_id = extract_cookie(&headers, "chalk_portal");
    let portal_session = if let Some(sid) = session_id {
        state.repo.get_portal_session(&sid).await.map_err(oidc_db_err)?
    } else {
        None
    };

    // Filter out expired sessions
    let portal_session = portal_session.filter(|s| s.expires_at > Utc::now());

    match portal_session {
        None => {
            // Redirect to login, preserving all OIDC params
            let return_path = build_authorize_return_url(&state.public_url, &params);
            let login_url = format!(
                "/idp/login?redirect={}",
                urlencoding::encode(&return_path)
            );
            Ok(Redirect::temporary(&login_url).into_response())
        }
        Some(session) => {
            // Show consent page
            let user = state
                .repo
                .get_user(&session.user_sourced_id)
                .await
                .map_err(oidc_db_err)?
                .ok_or_else(|| OidcError::internal("session user not found"))?;

            let scopes: Vec<String> = params
                .scope
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();

            let template = ConsentTemplate {
                app_name: partner.name.clone(),
                scopes,
                user_name: format!("{} {}", user.given_name, user.family_name),
                user_email: user.email.clone().unwrap_or_default(),
                client_id: params.client_id,
                redirect_uri: params.redirect_uri,
                response_type: params.response_type,
                scope: params.scope,
                state: params.state.unwrap_or_default(),
                nonce: params.nonce.unwrap_or_default(),
            };

            Ok(Html(template.render().map_err(|e| {
                OidcError::internal(format!("template error: {e}"))
            })?)
            .into_response())
        }
    }
}

fn build_authorize_return_url(public_url: &str, params: &AuthorizeParams) -> String {
    let mut url = format!(
        "{}/idp/oidc/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}",
        public_url,
        urlencoding::encode(&params.client_id),
        urlencoding::encode(&params.redirect_uri),
        urlencoding::encode(&params.response_type),
        urlencoding::encode(&params.scope),
    );
    if let Some(ref s) = params.state {
        url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    if let Some(ref n) = params.nonce {
        url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
    }
    url
}

/// Extract a named cookie value from headers.
fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|pair| {
            let pair = pair.trim();
            let (k, v) = pair.split_once('=')?;
            if k.trim() == name {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
}

// -- Consent POST (authorize decision) --

#[derive(Deserialize)]
struct ConsentForm {
    consent: String,
    client_id: String,
    redirect_uri: String,
    #[allow(dead_code)]
    response_type: String,
    scope: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

async fn oidc_authorize_consent(
    State(state): State<Arc<OidcState>>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Result<Response, OidcError> {
    if form.consent != "approve" {
        // User denied — redirect back with error
        let deny_url = format!(
            "{}?error=access_denied&state={}",
            form.redirect_uri,
            form.state.as_deref().unwrap_or("")
        );
        return Ok(Redirect::temporary(&deny_url).into_response());
    }

    // Validate partner
    let partner = state
        .find_partner(&form.client_id)
        .ok_or_else(|| OidcError::bad_request("unknown client_id"))?;

    if !partner.oidc_redirect_uris.contains(&form.redirect_uri) {
        return Err(OidcError::bad_request("invalid redirect_uri"));
    }

    // Get portal session
    let session_id = extract_cookie(&headers, "chalk_portal")
        .ok_or_else(|| OidcError::unauthorized("no portal session"))?;
    let session = state
        .repo
        .get_portal_session(&session_id)
        .await
        .map_err(oidc_db_err)?
        .filter(|s| s.expires_at > Utc::now())
        .ok_or_else(|| OidcError::unauthorized("session expired"))?;

    // Generate authorization code
    let code = generate_random_hex(32);
    let now = Utc::now();

    let oidc_code = OidcAuthorizationCode {
        code: code.clone(),
        client_id: form.client_id,
        user_sourced_id: session.user_sourced_id,
        redirect_uri: form.redirect_uri.clone(),
        scope: form.scope,
        nonce: form.nonce,
        created_at: now,
        expires_at: now + Duration::minutes(10),
    };

    state
        .repo
        .create_oidc_code(&oidc_code)
        .await
        .map_err(oidc_db_err)?;

    // Redirect with code and state
    let mut redirect_url = format!("{}?code={}", form.redirect_uri, code);
    if let Some(ref s) = form.state {
        if !s.is_empty() {
            redirect_url.push_str(&format!("&state={}", urlencoding::encode(s)));
        }
    }

    Ok(Redirect::temporary(&redirect_url).into_response())
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
    id_token: String,
}

/// JWT claims for the id_token.
#[derive(Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    name: String,
    given_name: String,
    family_name: String,
    role: String,
}

/// Extract client credentials from Basic auth header or form body.
fn extract_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Option<(String, String)> {
    // Try HTTP Basic first
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    if let Ok(cred_str) = String::from_utf8(decoded) {
                        if let Some((id, secret)) = cred_str.split_once(':') {
                            return Some((id.to_string(), secret.to_string()));
                        }
                    }
                }
            }
        }
    }

    // Fall back to form body
    match (form_client_id, form_client_secret) {
        (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => {
            Some((id.to_string(), secret.to_string()))
        }
        _ => None,
    }
}

async fn oidc_token(
    State(state): State<Arc<OidcState>>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OidcError> {
    if form.grant_type != "authorization_code" {
        return Err(OidcError::token_error(
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
    .ok_or_else(|| OidcError::token_error("invalid_client", "client credentials required"))?;

    // Look up the authorization code
    let oidc_code = state
        .repo
        .get_oidc_code(&form.code)
        .await
        .map_err(oidc_db_err)?
        .ok_or_else(|| OidcError::token_error("invalid_grant", "authorization code not found"))?;

    // Delete the code (single use)
    state
        .repo
        .delete_oidc_code(&form.code)
        .await
        .map_err(oidc_db_err)?;

    // Validate code hasn't expired
    if oidc_code.expires_at < Utc::now() {
        return Err(OidcError::token_error("invalid_grant", "authorization code expired"));
    }

    // Validate client_id matches
    if oidc_code.client_id != client_id {
        return Err(OidcError::token_error("invalid_grant", "client_id mismatch"));
    }

    // Validate client_secret
    let partner = state
        .find_partner(&client_id)
        .ok_or_else(|| OidcError::token_error("invalid_client", "unknown client_id"))?;

    if partner.oidc_client_secret.as_deref() != Some(&client_secret) {
        return Err(OidcError::token_error("invalid_client", "invalid client_secret"));
    }

    // Validate redirect_uri
    if oidc_code.redirect_uri != form.redirect_uri {
        return Err(OidcError::token_error("invalid_grant", "redirect_uri mismatch"));
    }

    // Look up the user
    let user = state
        .repo
        .get_user(&oidc_code.user_sourced_id)
        .await
        .map_err(oidc_db_err)?
        .ok_or_else(|| OidcError::token_error("server_error", "user not found"))?;

    // Generate id_token JWT
    let now = Utc::now();
    let claims = IdTokenClaims {
        iss: state.public_url.clone(),
        sub: user.sourced_id.clone(),
        aud: client_id.clone(),
        exp: (now + Duration::hours(1)).timestamp(),
        iat: now.timestamp(),
        nonce: oidc_code.nonce,
        email: user.email.clone(),
        name: format!("{} {}", user.given_name, user.family_name),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
        role: format!("{:?}", user.role).to_lowercase(),
    };

    let encoding_key = EncodingKey::from_rsa_pem(&state.signing_key)
        .map_err(|e| OidcError::internal(format!("signing key error: {e}")))?;

    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some("chalk-oidc-1".to_string());

    let id_token = encode(&jwt_header, &claims, &encoding_key)
        .map_err(|e| OidcError::internal(format!("JWT encoding error: {e}")))?;

    // Generate access token and store it as an OIDC code with "access_token" scope marker
    let access_token = generate_random_hex(64);
    let access_code = OidcAuthorizationCode {
        code: access_token.clone(),
        client_id,
        user_sourced_id: user.sourced_id,
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
        .map_err(oidc_db_err)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        id_token,
    }))
}

// -- UserInfo Endpoint --

#[derive(Serialize)]
struct UserInfoResponse {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    name: String,
    given_name: String,
    family_name: String,
    role: String,
}

async fn oidc_userinfo(
    State(state): State<Arc<OidcState>>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, OidcError> {
    // Extract Bearer token
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| OidcError::unauthorized("Bearer token required"))?;

    // Look up the access token
    let token_record = state
        .repo
        .get_oidc_code(bearer)
        .await
        .map_err(oidc_db_err)?
        .ok_or_else(|| OidcError::unauthorized("invalid access token"))?;

    // Verify it's an access token
    if !token_record.scope.starts_with("access_token") {
        return Err(OidcError::unauthorized("invalid access token"));
    }

    // Check expiry
    if token_record.expires_at < Utc::now() {
        return Err(OidcError::unauthorized("access token expired"));
    }

    // Look up user
    let user = state
        .repo
        .get_user(&token_record.user_sourced_id)
        .await
        .map_err(oidc_db_err)?
        .ok_or_else(|| OidcError::internal("user not found"))?;

    Ok(Json(UserInfoResponse {
        sub: user.sourced_id,
        email: user.email,
        name: format!("{} {}", user.given_name, user.family_name),
        given_name: user.given_name,
        family_name: user.family_name,
        role: format!("{:?}", user.role).to_lowercase(),
    }))
}

// -- Router --

/// Build the OIDC router. Mount at `/idp/oidc`.
pub fn oidc_router(state: Arc<OidcState>) -> Router {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(oidc_discovery),
        )
        .route("/jwks", get(oidc_jwks))
        .route(
            "/authorize",
            get(oidc_authorize).post(oidc_authorize_consent),
        )
        .route("/token", post(oidc_token))
        .route("/userinfo", get(oidc_userinfo))
        .with_state(state)
}

// -- Helpers --

/// Generate a cryptographically random hex string of `byte_count` bytes.
fn generate_random_hex(byte_count: usize) -> String {
    let mut bytes = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

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

/// OIDC-specific error response.
struct OidcError {
    status: StatusCode,
    error: String,
    description: String,
}

impl OidcError {
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

impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.error,
            "error_description": self.description,
        });
        (self.status, Json(body)).into_response()
    }
}

fn oidc_db_err(e: ChalkError) -> OidcError {
    OidcError::internal(format!("database error: {e}"))
}

// -- Unit Tests --

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use chalk_core::db::sqlite::SqliteRepository;
    use chalk_core::models::sso::{SsoPartner, SsoPartnerSource, SsoProtocol};
    use chrono::Utc;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use tower::ServiceExt;

    /// Generate a test RSA key pair and return PEM bytes.
    fn test_signing_key() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let private_key =
            rsa::RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("failed to encode PEM");
        pem.as_bytes().to_vec()
    }

    fn test_partner() -> SsoPartner {
        SsoPartner {
            id: "partner-oidc-1".to_string(),
            name: "Test OIDC App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::Oidc,
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
        let pool = DatabasePool::new_sqlite_memory()
            .await
            .expect("memory DB");
        match pool {
            DatabasePool::Sqlite(p) => SqliteRepository::new(p),
        }
    }

    fn test_state(repo: SqliteRepository, key: Vec<u8>) -> Arc<OidcState> {
        Arc::new(OidcState {
            repo: Arc::new(repo),
            partners: vec![test_partner()],
            signing_key: key,
            public_url: "https://chalk.school.edu".to_string(),
        })
    }

    fn test_app(state: Arc<OidcState>) -> Router {
        oidc_router(state)
    }

    #[tokio::test]
    async fn discovery_has_all_required_fields() {
        let key = test_signing_key();
        let repo = test_repo().await;
        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(doc["issuer"], "https://chalk.school.edu");
        assert_eq!(
            doc["authorization_endpoint"],
            "https://chalk.school.edu/idp/oidc/authorize"
        );
        assert_eq!(
            doc["token_endpoint"],
            "https://chalk.school.edu/idp/oidc/token"
        );
        assert_eq!(
            doc["userinfo_endpoint"],
            "https://chalk.school.edu/idp/oidc/userinfo"
        );
        assert_eq!(
            doc["jwks_uri"],
            "https://chalk.school.edu/idp/oidc/jwks"
        );
        assert!(doc["response_types_supported"].is_array());
        assert!(doc["scopes_supported"].is_array());
        assert!(doc["grant_types_supported"].is_array());
        assert!(doc["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("RS256")));
    }

    #[tokio::test]
    async fn jwks_returns_valid_jwk_format() {
        let key = test_signing_key();
        let repo = test_repo().await;
        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(jwks["keys"].is_array());
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);

        let key = &keys[0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["kid"], "chalk-oidc-1");
        assert!(key["n"].is_string());
        assert!(key["e"].is_string());
        // Verify n and e are valid base64url
        assert!(URL_SAFE_NO_PAD
            .decode(key["n"].as_str().unwrap())
            .is_ok());
        assert!(URL_SAFE_NO_PAD
            .decode(key["e"].as_str().unwrap())
            .is_ok());
    }

    #[tokio::test]
    async fn authorize_rejects_unknown_client_id() {
        let key = test_signing_key();
        let repo = test_repo().await;
        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/authorize?client_id=unknown&redirect_uri=https://evil.com&response_type=code&scope=openid")
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
    async fn authorize_rejects_invalid_redirect_uri() {
        let key = test_signing_key();
        let repo = test_repo().await;
        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/authorize?client_id=test-client&redirect_uri=https://evil.com/callback&response_type=code&scope=openid")
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
            .contains("redirect_uri"));
    }

    #[tokio::test]
    async fn token_rejects_invalid_client_credentials() {
        let key = test_signing_key();
        let repo = test_repo().await;

        // Create a valid auth code first
        let now = Utc::now();
        let code = OidcAuthorizationCode {
            code: "test-code-123".to_string(),
            client_id: "test-client".to_string(),
            user_sourced_id: "user-1".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            nonce: None,
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };
        repo.create_oidc_code(&code).await.unwrap();

        let state = test_state(repo, key);
        let app = test_app(state);

        let body = "grant_type=authorization_code&code=test-code-123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&client_secret=wrong-secret";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(err["error"], "invalid_client");
    }

    #[tokio::test]
    async fn token_rejects_expired_code() {
        let key = test_signing_key();
        let repo = test_repo().await;

        // Create an expired auth code
        let now = Utc::now();
        let code = OidcAuthorizationCode {
            code: "expired-code".to_string(),
            client_id: "test-client".to_string(),
            user_sourced_id: "user-1".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid".to_string(),
            nonce: None,
            created_at: now - Duration::minutes(20),
            expires_at: now - Duration::minutes(10),
        };
        repo.create_oidc_code(&code).await.unwrap();

        let state = test_state(repo, key);
        let app = test_app(state);

        let body = "grant_type=authorization_code&code=expired-code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&client_secret=test-secret";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(err["error"], "invalid_grant");
        assert!(err["error_description"]
            .as_str()
            .unwrap()
            .contains("expired"));
    }

    #[tokio::test]
    async fn full_token_and_userinfo_flow() {
        use chalk_core::db::repository::{OrgRepository, UserRepository};
        use chalk_core::models::common::{OrgType, RoleType, Status};
        use chalk_core::models::org::Org;
        use chalk_core::models::user::User;

        let key = test_signing_key();
        let repo = test_repo().await;

        // Create org first (FK constraint)
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

        // Create a test user
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

        // Create a valid auth code
        let now = Utc::now();
        let code = OidcAuthorizationCode {
            code: "valid-code".to_string(),
            client_id: "test-client".to_string(),
            user_sourced_id: "user-1".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            nonce: Some("test-nonce".to_string()),
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };
        repo.create_oidc_code(&code).await.unwrap();

        let state = test_state(repo, key);

        // -- Token request --
        let app = test_app(Arc::clone(&state));
        let body = "grant_type=authorization_code&code=valid-code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&client_secret=test-secret";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
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
        assert!(token_resp["id_token"].is_string());

        let access_token = token_resp["access_token"].as_str().unwrap();

        // -- Verify id_token is a valid JWT --
        let id_token = token_resp["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        // Decode payload
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(claims["sub"], "user-1");
        assert_eq!(claims["aud"], "test-client");
        assert_eq!(claims["email"], "jdoe@school.edu");
        assert_eq!(claims["given_name"], "John");
        assert_eq!(claims["family_name"], "Doe");
        assert_eq!(claims["nonce"], "test-nonce");
        assert_eq!(claims["role"], "student");

        // -- UserInfo request --
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header("authorization", format!("Bearer {}", access_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let userinfo: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(userinfo["sub"], "user-1");
        assert_eq!(userinfo["email"], "jdoe@school.edu");
        assert_eq!(userinfo["name"], "John Doe");
        assert_eq!(userinfo["given_name"], "John");
        assert_eq!(userinfo["family_name"], "Doe");
        assert_eq!(userinfo["role"], "student");
    }

    #[tokio::test]
    async fn userinfo_rejects_missing_bearer() {
        let key = test_signing_key();
        let repo = test_repo().await;
        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn userinfo_rejects_invalid_token() {
        let key = test_signing_key();
        let repo = test_repo().await;
        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header("authorization", "Bearer invalid-token-xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn extract_cookie_parses_correctly() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "session=abc123; chalk_portal=portal-456; other=val"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_cookie(&headers, "chalk_portal"),
            Some("portal-456".to_string())
        );
        assert_eq!(
            extract_cookie(&headers, "session"),
            Some("abc123".to_string())
        );
        assert_eq!(extract_cookie(&headers, "missing"), None);
    }

    #[test]
    fn extract_cookie_returns_none_for_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie(&headers, "chalk_portal"), None);
    }

    #[test]
    fn generate_random_hex_correct_length() {
        let hex = generate_random_hex(32);
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        let hex2 = generate_random_hex(64);
        assert_eq!(hex2.len(), 128);
    }

    #[test]
    fn urlencoding_encode_preserves_unreserved() {
        assert_eq!(urlencoding::encode("hello"), "hello");
        assert_eq!(urlencoding::encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn urlencoding_encode_encodes_special() {
        assert_eq!(urlencoding::encode("a b"), "a%20b");
        assert_eq!(urlencoding::encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn client_credentials_from_basic_auth() {
        let mut headers = HeaderMap::new();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("my-client:my-secret");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        let creds = extract_client_credentials(&headers, None, None);
        assert_eq!(
            creds,
            Some(("my-client".to_string(), "my-secret".to_string()))
        );
    }

    #[test]
    fn client_credentials_from_form_body() {
        let headers = HeaderMap::new();
        let creds =
            extract_client_credentials(&headers, Some("form-client"), Some("form-secret"));
        assert_eq!(
            creds,
            Some(("form-client".to_string(), "form-secret".to_string()))
        );
    }

    #[test]
    fn client_credentials_basic_auth_takes_precedence() {
        let mut headers = HeaderMap::new();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("basic-client:basic-secret");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        let creds = extract_client_credentials(
            &headers,
            Some("form-client"),
            Some("form-secret"),
        );
        assert_eq!(
            creds,
            Some(("basic-client".to_string(), "basic-secret".to_string()))
        );
    }

    #[tokio::test]
    async fn oidc_state_find_partner_filters_by_protocol() {
        let repo = test_repo().await;
        let mut saml_partner = test_partner();
        saml_partner.protocol = SsoProtocol::Saml;
        saml_partner.oidc_client_id = Some("test-client".to_string());

        let state = OidcState {
            repo: Arc::new(repo),
            partners: vec![saml_partner],
            signing_key: vec![],
            public_url: String::new(),
        };

        assert!(state.find_partner("test-client").is_none());
    }

    #[tokio::test]
    async fn oidc_state_find_partner_filters_disabled() {
        let repo = test_repo().await;
        let mut disabled = test_partner();
        disabled.enabled = false;

        let state = OidcState {
            repo: Arc::new(repo),
            partners: vec![disabled],
            signing_key: vec![],
            public_url: String::new(),
        };

        assert!(state.find_partner("test-client").is_none());
    }
}
