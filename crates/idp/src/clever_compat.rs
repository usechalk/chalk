//! Clever-compatible SSO endpoints for Chalk IDP.
//!
//! Exposes Clever's exact API paths and response shapes while reusing
//! the same OIDC infrastructure (OidcAuthorizationCode table, portal sessions, etc.).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chalk_core::db::repository::{
    ClassRepository, EnrollmentRepository, ExternalIdRepository, OidcCodeRepository, OrgRepository,
    PortalSessionRepository, UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::error::ChalkError;
use chalk_core::models::common::{EnrollmentRole, RoleType};
use chalk_core::models::sso::{OidcAuthorizationCode, SsoPartner, SsoProtocol};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::compat_common::{extract_client_credentials, extract_cookie, generate_random_hex};

/// Shared state for Clever-compat routes.
pub struct CleverCompatState {
    pub repo: Arc<SqliteRepository>,
    pub partners: Vec<SsoPartner>,
    pub signing_key: Vec<u8>,
    pub public_url: String,
    pub district_id: String,
    pub district_name: String,
}

impl CleverCompatState {
    /// Find a CleverCompat partner by client_id.
    fn find_partner(&self, client_id: &str) -> Option<&SsoPartner> {
        self.partners.iter().find(|p| {
            p.protocol == SsoProtocol::CleverCompat
                && p.enabled
                && p.oidc_client_id.as_deref() == Some(client_id)
        })
    }
}

// -- Discovery Document --

#[derive(Serialize)]
struct CleverDiscoveryDocument {
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

async fn clever_discovery(
    State(state): State<Arc<CleverCompatState>>,
) -> Json<CleverDiscoveryDocument> {
    let base = &state.public_url;
    Json(CleverDiscoveryDocument {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/idp/clever/oauth/authorize"),
        token_endpoint: format!("{base}/idp/clever/oauth/tokens"),
        userinfo_endpoint: format!("{base}/idp/clever/userinfo"),
        jwks_uri: format!("{base}/idp/clever/jwks"),
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

async fn clever_jwks(
    State(state): State<Arc<CleverCompatState>>,
) -> Result<Json<JwkSet>, CleverError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    let rsa_key = rsa::RsaPrivateKey::from_pkcs1_pem(
        std::str::from_utf8(&state.signing_key)
            .map_err(|e| CleverError::internal(format!("invalid PEM encoding: {e}")))?,
    )
    .map_err(|e| CleverError::internal(format!("invalid RSA private key: {e}")))?;

    let public_key = rsa_key.to_public_key();
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();

    let jwk = Jwk {
        kty: "RSA".to_string(),
        use_: "sig".to_string(),
        alg: "RS256".to_string(),
        kid: "chalk-clever-1".to_string(),
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
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn clever_authorize(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, CleverError> {
    // Validate client_id
    let partner = state
        .find_partner(&params.client_id)
        .ok_or_else(|| CleverError::bad_request("unknown client_id"))?;

    // Validate redirect_uri
    if !partner.oidc_redirect_uris.contains(&params.redirect_uri) {
        return Err(CleverError::bad_request("invalid redirect_uri"));
    }

    // Check for portal session cookie
    let session_id = extract_cookie(&headers, "chalk_portal");
    let portal_session = if let Some(sid) = session_id {
        state
            .repo
            .get_portal_session(&sid)
            .await
            .map_err(clever_db_err)?
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
            // No consent page for Clever — generate code immediately
            let code = generate_clever_id();
            let now = Utc::now();

            let oidc_code = OidcAuthorizationCode {
                code: code.clone(),
                client_id: params.client_id,
                user_sourced_id: session.user_sourced_id,
                redirect_uri: params.redirect_uri.clone(),
                scope: params.scope.unwrap_or_else(|| "openid".to_string()),
                nonce: None,
                created_at: now,
                expires_at: now + Duration::minutes(10),
            };

            state
                .repo
                .create_oidc_code(&oidc_code)
                .await
                .map_err(clever_db_err)?;

            let mut redirect_url = format!("{}?code={}", params.redirect_uri, code);
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
        "{}/idp/clever/oauth/authorize?client_id={}&redirect_uri={}",
        public_url,
        urlencoding::encode(&params.client_id),
        urlencoding::encode(&params.redirect_uri),
    );
    if let Some(ref rt) = params.response_type {
        url.push_str(&format!("&response_type={}", urlencoding::encode(rt)));
    }
    if let Some(ref s) = params.state {
        url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    if let Some(ref sc) = params.scope {
        url.push_str(&format!("&scope={}", urlencoding::encode(sc)));
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
struct CleverTokenResponse {
    access_token: String,
    token_type: String,
    id_token: String,
    expires_in: i64,
}

/// JWT claims for the id_token.
#[derive(Serialize)]
struct CleverIdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    district_id: String,
    user_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    given_name: String,
    family_name: String,
}

async fn clever_token(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<TokenRequest>,
) -> Result<Json<CleverTokenResponse>, CleverError> {
    if form.grant_type != "authorization_code" {
        return Err(CleverError::token_error(
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
    .ok_or_else(|| CleverError::token_error("invalid_client", "client credentials required"))?;

    // Look up the authorization code
    let oidc_code = state
        .repo
        .get_oidc_code(&form.code)
        .await
        .map_err(clever_db_err)?
        .ok_or_else(|| CleverError::token_error("invalid_grant", "authorization code not found"))?;

    // Validate code hasn't expired
    if oidc_code.expires_at < Utc::now() {
        return Err(CleverError::token_error(
            "invalid_grant",
            "authorization code expired",
        ));
    }

    // Validate client_id matches
    if oidc_code.client_id != client_id {
        return Err(CleverError::token_error(
            "invalid_grant",
            "client_id mismatch",
        ));
    }

    // Validate client_secret
    let partner = state
        .find_partner(&client_id)
        .ok_or_else(|| CleverError::token_error("invalid_client", "unknown client_id"))?;

    if partner.oidc_client_secret.as_deref() != Some(&client_secret) {
        return Err(CleverError::token_error(
            "invalid_client",
            "invalid client_secret",
        ));
    }

    // Validate redirect_uri
    if oidc_code.redirect_uri != form.redirect_uri {
        return Err(CleverError::token_error(
            "invalid_grant",
            "redirect_uri mismatch",
        ));
    }

    // Delete the code (single use) — after all validations pass
    state
        .repo
        .delete_oidc_code(&form.code)
        .await
        .map_err(clever_db_err)?;

    // Look up the user
    let user = state
        .repo
        .get_user(&oidc_code.user_sourced_id)
        .await
        .map_err(clever_db_err)?
        .ok_or_else(|| CleverError::token_error("server_error", "user not found"))?;

    // Generate id_token JWT
    let now = Utc::now();
    let claims = CleverIdTokenClaims {
        iss: state.public_url.clone(),
        sub: user.sourced_id.clone(),
        aud: client_id.clone(),
        exp: (now + Duration::hours(1)).timestamp(),
        iat: now.timestamp(),
        district_id: state.district_id.clone(),
        user_type: role_to_clever_type(&user.role),
        email: user.email.clone(),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
    };

    let encoding_key = EncodingKey::from_rsa_pem(&state.signing_key)
        .map_err(|e| CleverError::internal(format!("signing key error: {e}")))?;

    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some("chalk-clever-1".to_string());

    let id_token = encode(&jwt_header, &claims, &encoding_key)
        .map_err(|e| CleverError::internal(format!("JWT encoding error: {e}")))?;

    // Generate access token and store it
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
        .map_err(clever_db_err)?;

    Ok(Json(CleverTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        id_token,
        expires_in: 3600,
    }))
}

// -- /v3.0/me and /v3.1/me --

#[derive(Serialize)]
struct CleverMeResponse {
    #[serde(rename = "type")]
    type_: String,
    data: CleverMeData,
    links: Vec<CleverLink>,
}

#[derive(Serialize)]
struct CleverMeData {
    id: String,
    district: String,
    #[serde(rename = "type")]
    type_: String,
    authorized_by: String,
    name: CleverName,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    roles: serde_json::Value,
}

#[derive(Serialize)]
struct CleverName {
    first: String,
    last: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    middle: Option<String>,
}

#[derive(Serialize)]
struct CleverLink {
    rel: String,
    uri: String,
}

async fn clever_me(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
) -> Result<Json<CleverMeResponse>, CleverError> {
    let (user, clever_id) = extract_bearer_user(&state, &headers).await?;

    let user_type = role_to_clever_type(&user.role);
    let roles = build_clever_roles(&user.role);

    Ok(Json(CleverMeResponse {
        type_: "user".to_string(),
        data: CleverMeData {
            id: clever_id.clone(),
            district: state.district_id.clone(),
            type_: user_type,
            authorized_by: "district".to_string(),
            name: CleverName {
                first: user.given_name.clone(),
                last: user.family_name.clone(),
                middle: user.middle_name.clone(),
            },
            email: user.email.clone(),
            roles,
        },
        links: vec![
            CleverLink {
                rel: "self".to_string(),
                uri: format!("/v3.1/users/{clever_id}"),
            },
            CleverLink {
                rel: "canonical".to_string(),
                uri: format!("/v3.1/users/{clever_id}"),
            },
        ],
    }))
}

// -- /v3.0/users/{id} and /v3.1/users/{id} --

#[derive(Serialize)]
struct CleverUserResponse {
    data: CleverUserData,
    links: Vec<CleverLink>,
}

#[derive(Serialize)]
struct CleverUserData {
    id: String,
    district: String,
    #[serde(rename = "type")]
    type_: String,
    name: CleverName,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    roles: serde_json::Value,
    created: String,
    last_modified: String,
}

async fn clever_user_by_id(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<CleverUserResponse>, CleverError> {
    // Verify bearer token is valid
    verify_bearer(&state, &headers).await?;

    // Look up user by clever ID (stored in external_ids)
    let user = find_user_by_clever_id(&state, &user_id).await?;

    let user_type = role_to_clever_type(&user.role);
    let roles = build_clever_roles(&user.role);

    Ok(Json(CleverUserResponse {
        data: CleverUserData {
            id: user_id.clone(),
            district: state.district_id.clone(),
            type_: user_type,
            name: CleverName {
                first: user.given_name.clone(),
                last: user.family_name.clone(),
                middle: user.middle_name.clone(),
            },
            email: user.email.clone(),
            roles,
            created: user.date_last_modified.to_rfc3339(),
            last_modified: user.date_last_modified.to_rfc3339(),
        },
        links: vec![
            CleverLink {
                rel: "self".to_string(),
                uri: format!("/v3.1/users/{user_id}"),
            },
            CleverLink {
                rel: "canonical".to_string(),
                uri: format!("/v3.1/users/{user_id}"),
            },
        ],
    }))
}

// -- /v3.0/users/{id}/sections --

#[derive(Serialize)]
struct CleverSectionsResponse {
    data: Vec<CleverSectionEntry>,
}

#[derive(Serialize)]
struct CleverSectionEntry {
    data: CleverSectionData,
}

#[derive(Serialize)]
struct CleverSectionData {
    id: String,
    name: String,
    district: String,
    school: String,
    course: String,
    subject: String,
    grade: String,
}

async fn clever_user_sections(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<CleverSectionsResponse>, CleverError> {
    verify_bearer(&state, &headers).await?;

    let user = find_user_by_clever_id(&state, &user_id).await?;

    let enrollments = state.repo.list_enrollments().await.map_err(clever_db_err)?;

    let user_enrollments: Vec<_> = enrollments
        .iter()
        .filter(|e| e.user == user.sourced_id)
        .collect();

    let mut sections = Vec::new();
    for enrollment in &user_enrollments {
        if let Ok(Some(class)) = state.repo.get_class(&enrollment.class).await {
            sections.push(CleverSectionEntry {
                data: CleverSectionData {
                    id: class.sourced_id.clone(),
                    name: class.title.clone(),
                    district: state.district_id.clone(),
                    school: class.school.clone(),
                    course: class.course.clone(),
                    subject: class.subjects.first().cloned().unwrap_or_default(),
                    grade: class.grades.first().cloned().unwrap_or_default(),
                },
            });
        }
    }

    Ok(Json(CleverSectionsResponse { data: sections }))
}

// -- /v3.0/users/{id}/schools --

#[derive(Serialize)]
struct CleverSchoolsResponse {
    data: Vec<CleverSchoolEntry>,
}

#[derive(Serialize)]
struct CleverSchoolEntry {
    data: CleverSchoolData,
}

#[derive(Serialize)]
struct CleverSchoolData {
    id: String,
    name: String,
    district: String,
    nces_id: Option<String>,
}

async fn clever_user_schools(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<CleverSchoolsResponse>, CleverError> {
    verify_bearer(&state, &headers).await?;

    let user = find_user_by_clever_id(&state, &user_id).await?;

    let mut schools = Vec::new();
    for org_id in &user.orgs {
        if let Ok(Some(org)) = state.repo.get_org(org_id).await {
            schools.push(CleverSchoolEntry {
                data: CleverSchoolData {
                    id: org.sourced_id.clone(),
                    name: org.name.clone(),
                    district: state.district_id.clone(),
                    nces_id: org.identifier.clone(),
                },
            });
        }
    }

    Ok(Json(CleverSchoolsResponse { data: schools }))
}

// -- /v3.0/users/{id}/myteachers --

#[derive(Serialize)]
struct CleverRelatedUsersResponse {
    data: Vec<CleverRelatedUserEntry>,
}

#[derive(Serialize)]
struct CleverRelatedUserEntry {
    data: CleverRelatedUserData,
}

#[derive(Serialize)]
struct CleverRelatedUserData {
    id: String,
    name: CleverName,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(rename = "type")]
    type_: String,
}

async fn clever_user_myteachers(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<CleverRelatedUsersResponse>, CleverError> {
    verify_bearer(&state, &headers).await?;

    let user = find_user_by_clever_id(&state, &user_id).await?;

    let enrollments = state.repo.list_enrollments().await.map_err(clever_db_err)?;

    // Find student's classes
    let student_classes: Vec<String> = enrollments
        .iter()
        .filter(|e| e.user == user.sourced_id)
        .map(|e| e.class.clone())
        .collect();

    // Find teachers in those classes
    let teacher_ids: Vec<String> = enrollments
        .iter()
        .filter(|e| student_classes.contains(&e.class) && e.role == EnrollmentRole::Teacher)
        .map(|e| e.user.clone())
        .collect();

    let mut teachers = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for tid in &teacher_ids {
        if seen.contains(tid) {
            continue;
        }
        seen.insert(tid.clone());
        if let Ok(Some(teacher)) = state.repo.get_user(tid).await {
            let teacher_clever_id = get_or_create_clever_id(&state, &teacher.sourced_id).await?;
            teachers.push(CleverRelatedUserEntry {
                data: CleverRelatedUserData {
                    id: teacher_clever_id,
                    name: CleverName {
                        first: teacher.given_name.clone(),
                        last: teacher.family_name.clone(),
                        middle: teacher.middle_name.clone(),
                    },
                    email: teacher.email.clone(),
                    type_: "teacher".to_string(),
                },
            });
        }
    }

    Ok(Json(CleverRelatedUsersResponse { data: teachers }))
}

// -- /v3.0/users/{id}/mystudents --

async fn clever_user_mystudents(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<CleverRelatedUsersResponse>, CleverError> {
    verify_bearer(&state, &headers).await?;

    let user = find_user_by_clever_id(&state, &user_id).await?;

    let enrollments = state.repo.list_enrollments().await.map_err(clever_db_err)?;

    // Find teacher's classes
    let teacher_classes: Vec<String> = enrollments
        .iter()
        .filter(|e| e.user == user.sourced_id)
        .map(|e| e.class.clone())
        .collect();

    // Find students in those classes
    let student_ids: Vec<String> = enrollments
        .iter()
        .filter(|e| teacher_classes.contains(&e.class) && e.role == EnrollmentRole::Student)
        .map(|e| e.user.clone())
        .collect();

    let mut students = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for sid in &student_ids {
        if seen.contains(sid) {
            continue;
        }
        seen.insert(sid.clone());
        if let Ok(Some(student)) = state.repo.get_user(sid).await {
            let student_clever_id = get_or_create_clever_id(&state, &student.sourced_id).await?;
            students.push(CleverRelatedUserEntry {
                data: CleverRelatedUserData {
                    id: student_clever_id,
                    name: CleverName {
                        first: student.given_name.clone(),
                        last: student.family_name.clone(),
                        middle: student.middle_name.clone(),
                    },
                    email: student.email.clone(),
                    type_: "student".to_string(),
                },
            });
        }
    }

    Ok(Json(CleverRelatedUsersResponse { data: students }))
}

// -- /v3.0/districts/{id} --

#[derive(Serialize)]
struct CleverDistrictResponse {
    data: CleverDistrictData,
}

#[derive(Serialize)]
struct CleverDistrictData {
    id: String,
    name: String,
}

async fn clever_district(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
    Path(district_id): Path<String>,
) -> Result<Json<CleverDistrictResponse>, CleverError> {
    verify_bearer(&state, &headers).await?;

    if district_id != state.district_id {
        return Err(CleverError::not_found("district not found"));
    }

    Ok(Json(CleverDistrictResponse {
        data: CleverDistrictData {
            id: state.district_id.clone(),
            name: state.district_name.clone(),
        },
    }))
}

// -- /userinfo --

#[derive(Serialize)]
struct CleverUserInfoResponse {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    name: String,
    given_name: String,
    family_name: String,
    role: String,
    district_id: String,
}

async fn clever_userinfo(
    State(state): State<Arc<CleverCompatState>>,
    headers: HeaderMap,
) -> Result<Json<CleverUserInfoResponse>, CleverError> {
    let bearer = extract_bearer(&headers)?;

    let token_record = state
        .repo
        .get_oidc_code(bearer)
        .await
        .map_err(clever_db_err)?
        .ok_or_else(|| CleverError::unauthorized("invalid access token"))?;

    let scopes: Vec<&str> = token_record.scope.split_whitespace().collect();
    if !scopes.contains(&"access_token") {
        return Err(CleverError::unauthorized("invalid access token"));
    }

    if token_record.expires_at < Utc::now() {
        return Err(CleverError::unauthorized("access token expired"));
    }

    let user = state
        .repo
        .get_user(&token_record.user_sourced_id)
        .await
        .map_err(clever_db_err)?
        .ok_or_else(|| CleverError::internal("user not found"))?;

    Ok(Json(CleverUserInfoResponse {
        sub: user.sourced_id.clone(),
        email: user.email.clone(),
        name: format!("{} {}", user.given_name, user.family_name),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
        role: format!("{:?}", user.role).to_lowercase(),
        district_id: state.district_id.clone(),
    }))
}

// -- Router --

/// Build the Clever-compat router. Mount at `/idp/clever`.
pub fn clever_compat_router(state: Arc<CleverCompatState>) -> Router {
    let api_routes = Router::new()
        .route("/me", get(clever_me))
        .route("/users/:id", get(clever_user_by_id))
        .route("/users/:id/sections", get(clever_user_sections))
        .route("/users/:id/schools", get(clever_user_schools))
        .route("/users/:id/myteachers", get(clever_user_myteachers))
        .route("/users/:id/mystudents", get(clever_user_mystudents))
        .route("/districts/:id", get(clever_district))
        .with_state(Arc::clone(&state));

    Router::new()
        .route("/.well-known/openid-configuration", get(clever_discovery))
        .route("/jwks", get(clever_jwks))
        .route("/oauth/authorize", get(clever_authorize))
        .route("/oauth/tokens", post(clever_token))
        .route("/userinfo", get(clever_userinfo))
        .nest("/v3.0", api_routes.clone())
        .nest("/v3.1", api_routes)
        .with_state(state)
}

// -- Helpers --

/// Generate a Clever-format ID: 24-char hex string (12 random bytes).
fn generate_clever_id() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Extract Bearer token string from headers.
fn extract_bearer(headers: &HeaderMap) -> Result<&str, CleverError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| CleverError::unauthorized("Bearer token required"))
}

/// Verify bearer token and return the token record.
async fn verify_bearer(
    state: &CleverCompatState,
    headers: &HeaderMap,
) -> Result<OidcAuthorizationCode, CleverError> {
    let bearer = extract_bearer(headers)?;

    let token_record = state
        .repo
        .get_oidc_code(bearer)
        .await
        .map_err(clever_db_err)?
        .ok_or_else(|| CleverError::unauthorized("invalid access token"))?;

    let scopes: Vec<&str> = token_record.scope.split_whitespace().collect();
    if !scopes.contains(&"access_token") {
        return Err(CleverError::unauthorized("invalid access token"));
    }

    if token_record.expires_at < Utc::now() {
        return Err(CleverError::unauthorized("access token expired"));
    }

    Ok(token_record)
}

/// Extract bearer user and their Clever ID.
async fn extract_bearer_user(
    state: &CleverCompatState,
    headers: &HeaderMap,
) -> Result<(chalk_core::models::user::User, String), CleverError> {
    let token_record = verify_bearer(state, headers).await?;

    let user = state
        .repo
        .get_user(&token_record.user_sourced_id)
        .await
        .map_err(clever_db_err)?
        .ok_or_else(|| CleverError::internal("user not found"))?;

    let clever_id = get_or_create_clever_id(state, &user.sourced_id).await?;

    Ok((user, clever_id))
}

/// Get or create a Clever-format external ID for a user.
async fn get_or_create_clever_id(
    state: &CleverCompatState,
    user_sourced_id: &str,
) -> Result<String, CleverError> {
    let ext_ids = state
        .repo
        .get_external_ids(user_sourced_id)
        .await
        .map_err(clever_db_err)?;

    if let Some(serde_json::Value::String(cid)) = ext_ids.get("clever_id") {
        return Ok(cid.clone());
    }

    // Generate and store new Clever ID
    let clever_id = generate_clever_id();
    let mut new_ids = ext_ids;
    new_ids.insert(
        "clever_id".to_string(),
        serde_json::Value::String(clever_id.clone()),
    );
    state
        .repo
        .set_external_ids(user_sourced_id, &new_ids)
        .await
        .map_err(clever_db_err)?;

    Ok(clever_id)
}

/// Find a user by their Clever external ID.
async fn find_user_by_clever_id(
    state: &CleverCompatState,
    clever_id: &str,
) -> Result<chalk_core::models::user::User, CleverError> {
    use chalk_core::models::sync::UserFilter;

    // List all users and find the one with the matching clever_id
    let filter = UserFilter::default();
    let users = state
        .repo
        .list_users(&filter)
        .await
        .map_err(clever_db_err)?;

    for user in &users {
        let ext_ids = state
            .repo
            .get_external_ids(&user.sourced_id)
            .await
            .map_err(clever_db_err)?;

        if let Some(serde_json::Value::String(cid)) = ext_ids.get("clever_id") {
            if cid == clever_id {
                return Ok(user.clone());
            }
        }
    }

    Err(CleverError::not_found("user not found"))
}

/// Convert RoleType to Clever user type string.
///
/// Uses exhaustive match (no wildcard) so that adding a new RoleType variant
/// produces a compile error, forcing an explicit mapping decision.
fn role_to_clever_type(role: &RoleType) -> String {
    match role {
        RoleType::Student => "student".to_string(),
        RoleType::Teacher => "teacher".to_string(),
        RoleType::Administrator => "district_admin".to_string(),
        RoleType::Aide | RoleType::Proctor | RoleType::Guardian | RoleType::Parent => {
            "staff".to_string()
        }
    }
}

/// Build Clever roles JSON object.
///
/// Uses exhaustive match (no wildcard) so that adding a new RoleType variant
/// produces a compile error, forcing an explicit mapping decision.
fn build_clever_roles(role: &RoleType) -> serde_json::Value {
    match role {
        RoleType::Student => serde_json::json!({
            "student": {}
        }),
        RoleType::Teacher => serde_json::json!({
            "teacher": {}
        }),
        RoleType::Administrator => serde_json::json!({
            "district_admin": {}
        }),
        RoleType::Aide | RoleType::Proctor | RoleType::Guardian | RoleType::Parent => {
            serde_json::json!({
                "staff": {}
            })
        }
    }
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

/// Clever-specific error response.
struct CleverError {
    status: StatusCode,
    error: String,
    description: String,
}

impl CleverError {
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

    fn not_found(desc: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: "not_found".to_string(),
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

impl IntoResponse for CleverError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.error,
            "error_description": self.description,
        });
        (self.status, Json(body)).into_response()
    }
}

fn clever_db_err(e: ChalkError) -> CleverError {
    CleverError::internal(format!("database error: {e}"))
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
            id: "partner-clever-1".to_string(),
            name: "Test Clever App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::CleverCompat,
            enabled: true,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles: vec![],
            saml_entity_id: None,
            saml_acs_url: None,
            oidc_client_id: Some("test-clever-client".to_string()),
            oidc_client_secret: Some("test-clever-secret".to_string()),
            oidc_redirect_uris: vec!["https://app.example.com/clever/callback".to_string()],
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

    fn test_state(repo: SqliteRepository, key: Vec<u8>) -> Arc<CleverCompatState> {
        Arc::new(CleverCompatState {
            repo: Arc::new(repo),
            partners: vec![test_partner()],
            signing_key: key,
            public_url: "https://chalk.school.edu".to_string(),
            district_id: "district-001".to_string(),
            district_name: "Test School District".to_string(),
        })
    }

    fn test_app(state: Arc<CleverCompatState>) -> Router {
        clever_compat_router(state)
    }

    async fn create_test_user(repo: &SqliteRepository) {
        use chalk_core::db::repository::{OrgRepository, UserRepository};
        use chalk_core::models::common::{OrgType, RoleType, Status};
        use chalk_core::models::org::Org;
        use chalk_core::models::user::User;

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
            middle_name: Some("M".to_string()),
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
    }

    async fn create_access_token(repo: &SqliteRepository) -> String {
        let now = Utc::now();
        let access_token = "test-access-token-123abc";
        let access_code = OidcAuthorizationCode {
            code: access_token.to_string(),
            client_id: "test-clever-client".to_string(),
            user_sourced_id: "user-1".to_string(),
            redirect_uri: String::new(),
            scope: "access_token openid".to_string(),
            nonce: None,
            created_at: now,
            expires_at: now + Duration::hours(1),
        };
        repo.create_oidc_code(&access_code).await.unwrap();
        access_token.to_string()
    }

    #[tokio::test]
    async fn discovery_has_clever_paths() {
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
            "https://chalk.school.edu/idp/clever/oauth/authorize"
        );
        assert_eq!(
            doc["token_endpoint"],
            "https://chalk.school.edu/idp/clever/oauth/tokens"
        );
        assert_eq!(
            doc["userinfo_endpoint"],
            "https://chalk.school.edu/idp/clever/userinfo"
        );
        assert_eq!(doc["jwks_uri"], "https://chalk.school.edu/idp/clever/jwks");
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
                    .uri("/oauth/authorize?client_id=unknown&redirect_uri=https://evil.com&response_type=code")
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
                    .uri("/oauth/authorize?client_id=test-clever-client&redirect_uri=https://evil.com/callback&response_type=code")
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
    async fn authorize_redirects_to_login_without_session() {
        let key = test_signing_key();
        let repo = test_repo().await;
        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/authorize?client_id=test-clever-client&redirect_uri=https://app.example.com/clever/callback&response_type=code")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/idp/login?redirect="));
    }

    #[tokio::test]
    async fn authorize_generates_code_with_session() {
        use chalk_core::db::repository::PortalSessionRepository;
        use chalk_core::models::sso::PortalSession;

        let key = test_signing_key();
        let repo = test_repo().await;
        create_test_user(&repo).await;

        // Create a portal session
        let now = Utc::now();
        let session = PortalSession {
            id: "session-abc".to_string(),
            user_sourced_id: "user-1".to_string(),
            created_at: now,
            expires_at: now + Duration::hours(8),
        };
        repo.create_portal_session(&session).await.unwrap();

        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/authorize?client_id=test-clever-client&redirect_uri=https://app.example.com/clever/callback&response_type=code&state=mystate")
                    .header("cookie", "chalk_portal=session-abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("https://app.example.com/clever/callback?code="));
        assert!(location.contains("state=mystate"));
        // Clever IDs are 24-char hex
        let code_start = location.find("code=").unwrap() + 5;
        let code_end = location.find("&state").unwrap_or(location.len());
        let code = &location[code_start..code_end];
        assert_eq!(code.len(), 24);
    }

    #[tokio::test]
    async fn token_exchange_works() {
        let key = test_signing_key();
        let repo = test_repo().await;
        create_test_user(&repo).await;

        // Create a valid auth code
        let now = Utc::now();
        let code = OidcAuthorizationCode {
            code: "clever-auth-code-123456".to_string(),
            client_id: "test-clever-client".to_string(),
            user_sourced_id: "user-1".to_string(),
            redirect_uri: "https://app.example.com/clever/callback".to_string(),
            scope: "openid".to_string(),
            nonce: None,
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };
        repo.create_oidc_code(&code).await.unwrap();

        let state = test_state(repo, key);
        let app = test_app(state);

        let body = "grant_type=authorization_code&code=clever-auth-code-123456&redirect_uri=https%3A%2F%2Fapp.example.com%2Fclever%2Fcallback&client_id=test-clever-client&client_secret=test-clever-secret";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/tokens")
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
        assert!(token_resp["access_token"].is_string());
        assert!(token_resp["id_token"].is_string());

        // Verify id_token contains district_id
        let id_token = token_resp["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(claims["district_id"], "district-001");
        assert_eq!(claims["user_type"], "student");
    }

    #[tokio::test]
    async fn me_returns_clever_format() {
        let key = test_signing_key();
        let repo = test_repo().await;
        create_test_user(&repo).await;
        let access_token = create_access_token(&repo).await;

        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v3.0/me")
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let me: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(me["type"], "user");
        assert_eq!(me["data"]["district"], "district-001");
        assert_eq!(me["data"]["type"], "student");
        assert_eq!(me["data"]["authorized_by"], "district");
        assert_eq!(me["data"]["name"]["first"], "John");
        assert_eq!(me["data"]["name"]["last"], "Doe");
        assert_eq!(me["data"]["name"]["middle"], "M");
        assert_eq!(me["data"]["email"], "jdoe@school.edu");
        assert!(me["data"]["roles"]["student"].is_object());
        assert!(me["links"].is_array());

        // Clever ID should be 24-char hex
        let clever_id = me["data"]["id"].as_str().unwrap();
        assert_eq!(clever_id.len(), 24);
    }

    #[tokio::test]
    async fn users_id_returns_user() {
        let key = test_signing_key();
        let repo = test_repo().await;
        create_test_user(&repo).await;
        let access_token = create_access_token(&repo).await;

        // First get the clever_id via /me
        let state = test_state(repo, key);
        let app = test_app(Arc::clone(&state));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v3.0/me")
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let me: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let clever_id = me["data"]["id"].as_str().unwrap();

        // Now fetch by ID
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v3.0/users/{clever_id}"))
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let user_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(user_resp["data"]["id"], clever_id);
        assert_eq!(user_resp["data"]["name"]["first"], "John");
        assert_eq!(user_resp["data"]["name"]["last"], "Doe");
        assert_eq!(user_resp["data"]["district"], "district-001");
        assert!(user_resp["links"].is_array());
    }

    #[tokio::test]
    async fn districts_id_returns_info() {
        let key = test_signing_key();
        let repo = test_repo().await;
        create_test_user(&repo).await;
        let access_token = create_access_token(&repo).await;

        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v3.0/districts/district-001")
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let district: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(district["data"]["id"], "district-001");
        assert_eq!(district["data"]["name"], "Test School District");
    }

    #[tokio::test]
    async fn userinfo_includes_district_id() {
        let key = test_signing_key();
        let repo = test_repo().await;
        create_test_user(&repo).await;
        let access_token = create_access_token(&repo).await;

        let state = test_state(repo, key);
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let userinfo: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(userinfo["sub"], "user-1");
        assert_eq!(userinfo["district_id"], "district-001");
        assert_eq!(userinfo["email"], "jdoe@school.edu");
        assert_eq!(userinfo["name"], "John Doe");
        assert_eq!(userinfo["given_name"], "John");
        assert_eq!(userinfo["family_name"], "Doe");
        assert_eq!(userinfo["role"], "student");
    }

    // -- role_to_clever_type exhaustive tests (Issue #6) --

    #[test]
    fn role_to_clever_type_student() {
        assert_eq!(role_to_clever_type(&RoleType::Student), "student");
    }

    #[test]
    fn role_to_clever_type_teacher() {
        assert_eq!(role_to_clever_type(&RoleType::Teacher), "teacher");
    }

    #[test]
    fn role_to_clever_type_administrator() {
        assert_eq!(
            role_to_clever_type(&RoleType::Administrator),
            "district_admin"
        );
    }

    #[test]
    fn role_to_clever_type_aide() {
        assert_eq!(role_to_clever_type(&RoleType::Aide), "staff");
    }

    #[test]
    fn role_to_clever_type_proctor() {
        assert_eq!(role_to_clever_type(&RoleType::Proctor), "staff");
    }

    #[test]
    fn role_to_clever_type_guardian() {
        assert_eq!(role_to_clever_type(&RoleType::Guardian), "staff");
    }

    #[test]
    fn role_to_clever_type_parent() {
        assert_eq!(role_to_clever_type(&RoleType::Parent), "staff");
    }

    // -- build_clever_roles exhaustive tests --

    #[test]
    fn build_clever_roles_student() {
        let roles = build_clever_roles(&RoleType::Student);
        assert!(roles["student"].is_object());
    }

    #[test]
    fn build_clever_roles_teacher() {
        let roles = build_clever_roles(&RoleType::Teacher);
        assert!(roles["teacher"].is_object());
    }

    #[test]
    fn build_clever_roles_administrator() {
        let roles = build_clever_roles(&RoleType::Administrator);
        assert!(roles["district_admin"].is_object());
    }

    #[test]
    fn build_clever_roles_aide_maps_to_staff() {
        let roles = build_clever_roles(&RoleType::Aide);
        assert!(roles["staff"].is_object());
    }

    #[test]
    fn build_clever_roles_proctor_maps_to_staff() {
        let roles = build_clever_roles(&RoleType::Proctor);
        assert!(roles["staff"].is_object());
    }

    #[test]
    fn build_clever_roles_guardian_maps_to_staff() {
        let roles = build_clever_roles(&RoleType::Guardian);
        assert!(roles["staff"].is_object());
    }

    #[test]
    fn build_clever_roles_parent_maps_to_staff() {
        let roles = build_clever_roles(&RoleType::Parent);
        assert!(roles["staff"].is_object());
    }
}
