//! Student/teacher launch portal — a standalone page where authenticated users
//! see their assigned SSO apps as tiles and can click to launch them.

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, State},
    http::header::SET_COOKIE,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chalk_core::db::repository::{
    AdminAuditRepository, ClassRepository, DemographicsRepository, EnrollmentRepository,
    PasswordRepository, PortalSessionRepository, QrBadgeRepository, SsoPartnerRepository,
    UserRepository,
};
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::http::extract_client_ip;
use chalk_core::models::common::{EnrollmentRole, RoleType, Status};
use chalk_core::models::idp::QrBadge;
use chalk_core::models::sso::{SsoPartner, SsoProtocol};
use chalk_core::passwords::PasswordGenerator;
use chrono::Utc;
use serde::Deserialize;

use crate::compat_common::extract_cookie;

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

#[derive(Template)]
#[template(path = "teacher_classes.html")]
struct TeacherClassesTemplate {
    user_display_name: String,
    user_role: String,
    classes: Vec<TeacherClassInfo>,
}

struct TeacherClassInfo {
    sourced_id: String,
    title: String,
    class_code: Option<String>,
    student_count: usize,
}

#[derive(Template)]
#[template(path = "class_roster.html")]
struct ClassRosterTemplate {
    user_display_name: String,
    user_role: String,
    class_title: String,
    class_id: String,
    students: Vec<RosterStudent>,
}

struct RosterStudent {
    sourced_id: String,
    given_name: String,
    family_name: String,
    username: String,
    grade: String,
}

#[derive(Template)]
#[template(path = "password_reset_result.html")]
struct PasswordResetResultTemplate {
    student_name: String,
    new_password: String,
    error: Option<String>,
}

#[derive(Deserialize)]
struct PasswordResetForm {
    custom_password: Option<String>,
}

// -- Router --

/// Build the portal router. Mount at `/portal`.
pub fn portal_router(state: Arc<crate::routes::IdpState>) -> Router {
    Router::new()
        .route("/", get(portal_home))
        .route("/launch/:partner_id", get(portal_launch))
        .route("/logout", post(portal_logout))
        .route("/my-classes", get(my_classes))
        .route("/my-classes/:class_id", get(class_roster))
        .route(
            "/my-classes/:class_id/reset-password/:student_id",
            post(reset_password),
        )
        .route(
            "/my-classes/:class_id/generate-badge/:student_id",
            post(generate_badge),
        )
        .with_state(state)
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
        SsoProtocol::CleverCompat => launch_clever_compat(&state, &partner),
        SsoProtocol::ClassLinkCompat => launch_classlink_compat(&state, &partner),
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

fn launch_clever_compat(state: &crate::routes::IdpState, partner: &SsoPartner) -> Response {
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
        None => return error_html("Partner has no redirect URI configured"),
    };

    let authorize_url = format!(
        "{}/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid%20profile%20email",
        base_url, urlencoding::encode(client_id), urlencoding::encode(redirect_uri),
    );

    Redirect::temporary(&authorize_url).into_response()
}

fn launch_classlink_compat(state: &crate::routes::IdpState, partner: &SsoPartner) -> Response {
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
        None => return error_html("Partner has no redirect URI configured"),
    };

    let authorize_url =
        format!(
        "{}/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20profile",
        base_url, urlencoding::encode(client_id), urlencoding::encode(redirect_uri),
    );

    Redirect::temporary(&authorize_url).into_response()
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
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
    );

    Redirect::temporary(&authorize_url).into_response()
}

/// Helper to validate a portal session and load the teacher user.
/// Returns an error response if the user is not a teacher.
async fn validate_teacher_session(
    repo: &SqliteRepository,
    headers: &axum::http::HeaderMap,
) -> Result<chalk_core::models::user::User, Response> {
    let session = validate_portal_session(repo, headers).await?;

    let user = repo
        .get_user(&session.user_sourced_id)
        .await
        .map_err(|_| Redirect::temporary("/idp/login?redirect=/portal").into_response())?
        .ok_or_else(|| Redirect::temporary("/idp/login?redirect=/portal").into_response())?;

    if user.role != RoleType::Teacher {
        return Err(error_html("Only teachers can access My Classes"));
    }

    Ok(user)
}

/// Validate that a teacher is actively enrolled in a given class.
/// Returns the teacher `User` on success, or an error response.
async fn validate_teacher_for_class(
    repo: &SqliteRepository,
    headers: &axum::http::HeaderMap,
    class_id: &str,
) -> Result<chalk_core::models::user::User, Response> {
    let teacher = validate_teacher_session(repo, headers).await?;

    let enrollments = repo
        .list_enrollments_for_user(&teacher.sourced_id)
        .await
        .map_err(|e| error_html(&format!("Failed to verify enrollment: {e}")))?;

    if !enrollments.iter().any(|e| {
        e.class == class_id && e.role == EnrollmentRole::Teacher && e.status == Status::Active
    }) {
        return Err(error_html(
            "You are not enrolled as a teacher in this class",
        ));
    }

    Ok(teacher)
}

/// Validate that a student is actively enrolled in a class, load and check the student user.
/// Returns the student `User` on success, or an error response.
async fn validate_student_in_class(
    repo: &SqliteRepository,
    class_id: &str,
    student_id: &str,
) -> Result<chalk_core::models::user::User, Response> {
    let class_enrollments = repo
        .list_enrollments_for_class(class_id)
        .await
        .map_err(|e| error_html(&format!("Failed to verify student enrollment: {e}")))?;

    if !class_enrollments.iter().any(|e| {
        e.user == student_id && e.role == EnrollmentRole::Student && e.status == Status::Active
    }) {
        return Err(error_html("Student is not enrolled in this class"));
    }

    let student = repo
        .get_user(student_id)
        .await
        .map_err(|e| error_html(&format!("Failed to load student: {e}")))?
        .ok_or_else(|| error_html("Student not found"))?;

    if student.status != Status::Active || !student.enabled_user {
        return Err(error_html("Student account is inactive or disabled"));
    }

    Ok(student)
}

/// GET /my-classes — List classes the teacher is enrolled in.
async fn my_classes(
    State(state): State<Arc<crate::routes::IdpState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let user = match validate_teacher_session(&state.repo, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let enrollments = match state.repo.list_enrollments_for_user(&user.sourced_id).await {
        Ok(e) => e,
        Err(e) => return error_html(&format!("Failed to load enrollments: {e}")),
    };

    // Filter for active teacher enrollments only
    let teacher_enrollments: Vec<_> = enrollments
        .into_iter()
        .filter(|e| e.role == EnrollmentRole::Teacher && e.status == Status::Active)
        .collect();

    let mut classes = Vec::new();
    for enrollment in &teacher_enrollments {
        if let Ok(Some(class)) = state.repo.get_class(&enrollment.class).await {
            // Count students in this class
            let student_count = match state
                .repo
                .list_enrollments_for_class(&class.sourced_id)
                .await
            {
                Ok(class_enrollments) => class_enrollments
                    .iter()
                    .filter(|e| e.role == EnrollmentRole::Student && e.status == Status::Active)
                    .count(),
                Err(_) => 0,
            };

            classes.push(TeacherClassInfo {
                sourced_id: class.sourced_id,
                title: class.title,
                class_code: class.class_code,
                student_count,
            });
        }
    }

    let template = TeacherClassesTemplate {
        user_display_name: format!("{} {}", user.given_name, user.family_name),
        user_role: "teacher".to_string(),
        classes,
    };

    Html(template.render().unwrap_or_default()).into_response()
}

/// GET /my-classes/:class_id — Show student roster for a specific class.
async fn class_roster(
    State(state): State<Arc<crate::routes::IdpState>>,
    Path(class_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let user = match validate_teacher_for_class(&state.repo, &headers, &class_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // Load the class
    let class = match state.repo.get_class(&class_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return error_html("Class not found"),
        Err(e) => return error_html(&format!("Failed to load class: {e}")),
    };

    // Load student enrollments
    let class_enrollments = match state.repo.list_enrollments_for_class(&class_id).await {
        Ok(e) => e,
        Err(e) => return error_html(&format!("Failed to load class enrollments: {e}")),
    };

    let mut students = Vec::new();
    for enrollment in class_enrollments
        .iter()
        .filter(|e| e.role == EnrollmentRole::Student && e.status == Status::Active)
    {
        if let Ok(Some(student_user)) = state.repo.get_user(&enrollment.user).await {
            if student_user.status != Status::Active || !student_user.enabled_user {
                continue;
            }
            students.push(RosterStudent {
                sourced_id: student_user.sourced_id,
                given_name: student_user.given_name,
                family_name: student_user.family_name,
                username: student_user.username,
                grade: student_user.grades.first().cloned().unwrap_or_default(),
            });
        }
    }

    let template = ClassRosterTemplate {
        user_display_name: format!("{} {}", user.given_name, user.family_name),
        user_role: "teacher".to_string(),
        class_title: class.title,
        class_id,
        students,
    };

    Html(template.render().unwrap_or_default()).into_response()
}

/// POST /my-classes/:class_id/reset-password/:student_id — Reset a student's password.
async fn reset_password(
    State(state): State<Arc<crate::routes::IdpState>>,
    Path((class_id, student_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    Form(form): Form<PasswordResetForm>,
) -> Response {
    let teacher = match validate_teacher_for_class(&state.repo, &headers, &class_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let student = match validate_student_in_class(&state.repo, &class_id, &student_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // Generate or use custom password
    let plaintext_password = if let Some(ref custom) = form.custom_password {
        let trimmed = custom.trim();
        if trimmed.is_empty() {
            return error_html("Custom password cannot be empty");
        }
        trimmed.to_string()
    } else {
        // Auto-generate using configured pattern or fallback
        let pattern = state
            .config
            .idp
            .default_password_pattern
            .as_deref()
            .unwrap_or("{firstName}{identifier}");

        let roles = vec!["student".to_string()];
        let generator = PasswordGenerator::new(pattern, &roles);
        let demographics = state
            .repo
            .get_demographics(&student.sourced_id)
            .await
            .ok()
            .flatten();
        match generator.generate_for_user(&student, demographics.as_ref()) {
            Ok(pw) => pw,
            Err(e) => {
                return Html(
                    PasswordResetResultTemplate {
                        student_name: format!("{} {}", student.given_name, student.family_name),
                        new_password: String::new(),
                        error: Some(format!(
                            "Auto-generate failed: {}. Please set a custom password instead.",
                            e
                        )),
                    }
                    .render()
                    .unwrap_or_default(),
                )
                .into_response();
            }
        }
    };

    // Hash and set password
    let hash = match crate::auth::hash_password(&plaintext_password) {
        Ok(h) => h,
        Err(e) => return error_html(&format!("Failed to hash password: {e}")),
    };

    if let Err(e) = state.repo.set_password_hash(&student_id, &hash).await {
        return error_html(&format!("Failed to set password: {e}"));
    }

    // Audit log
    let ip = extract_client_ip(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()));
    let details = format!(
        "Teacher {} ({}) reset password for student {} ({})",
        teacher.username, teacher.sourced_id, student.username, student.sourced_id
    );
    let _ = state
        .repo
        .log_admin_action("teacher_password_reset", Some(&details), ip.as_deref())
        .await;

    let template = PasswordResetResultTemplate {
        student_name: format!("{} {}", student.given_name, student.family_name),
        new_password: plaintext_password,
        error: None,
    };

    Html(template.render().unwrap_or_default()).into_response()
}

/// POST /my-classes/:class_id/generate-badge/:student_id — Generate QR badge for a student.
async fn generate_badge(
    State(state): State<Arc<crate::routes::IdpState>>,
    Path((class_id, student_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Response {
    let teacher = match validate_teacher_for_class(&state.repo, &headers, &class_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let student = match validate_student_in_class(&state.repo, &class_id, &student_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // Generate badge
    let badge_token = crate::qr::generate_badge_token();
    let badge = QrBadge {
        id: 0,
        badge_token: badge_token.clone(),
        user_sourced_id: student_id,
        is_active: true,
        created_at: Utc::now(),
        revoked_at: None,
    };

    match state.repo.create_badge(&badge).await {
        Ok(_) => {
            let qr_data = format!("chalk-badge:{}", badge_token);
            match crate::qr::generate_qr_png(&qr_data) {
                Ok(png) => {
                    // Audit log
                    let ip = extract_client_ip(
                        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
                    );
                    let details = format!(
                        "Teacher {} ({}) generated QR badge for student {} ({})",
                        teacher.username, teacher.sourced_id, student.username, student.sourced_id
                    );
                    let _ = state
                        .repo
                        .log_admin_action("teacher_badge_generate", Some(&details), ip.as_deref())
                        .await;

                    let base64_png = BASE64.encode(&png);
                    let html = format!(
                        r#"<div style="margin-top:10px;padding:12px;background:#f0f9ff;border:1px solid #93c5fd;border-radius:8px;display:inline-block;">
                            <img src="data:image/png;base64,{}" alt="QR Badge" style="width:200px;height:200px;">
                            <div style="font-size:12px;color:#1e40af;margin-top:8px;text-align:center;">QR Badge Generated</div>
                            <button onclick="this.parentElement.remove()" style="margin-top:6px;background:none;border:none;color:#6b7280;font-size:12px;cursor:pointer;text-decoration:underline;display:block;width:100%;text-align:center;">dismiss</button>
                        </div>"#,
                        base64_png
                    );
                    Html(html).into_response()
                }
                Err(e) => error_html(&format!("Failed to generate QR code: {e}")),
            }
        }
        Err(e) => error_html(&format!("Failed to create badge: {e}")),
    }
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
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;");
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Error</title>
        <style>body{{font-family:sans-serif;max-width:500px;margin:80px auto;text-align:center;}}
        .error{{background:#fef2f2;border:1px solid #fecaca;padding:24px;border-radius:8px;color:#991b1b;}}
        a{{color:#0d9488;margin-top:16px;display:inline-block;}}</style></head>
        <body><div class="error"><h2>Error</h2><p>{}</p></div>
        <a href="/portal">Back to Portal</a></body></html>"#,
        escaped
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
            ad_sync: Default::default(),
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

    #[tokio::test]
    async fn portal_launch_clever_compat_partner_redirects() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;

        let partner = SsoPartner {
            id: "partner-clever".to_string(),
            name: "Clever App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::CleverCompat,
            enabled: true,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles: vec![],
            saml_entity_id: None,
            saml_acs_url: None,
            oidc_client_id: Some("clever-client-1".to_string()),
            oidc_client_secret: Some("secret".to_string()),
            oidc_redirect_uris: vec!["https://clever-app.example.com/callback".to_string()],
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
                    .uri("/launch/partner-clever")
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
        assert!(location.contains("/oauth/authorize"));
        assert!(location.contains("clever-client-1"));
    }

    #[tokio::test]
    async fn portal_launch_classlink_compat_partner_redirects() {
        let repo = test_repo().await;
        insert_test_user(&repo).await;

        let partner = SsoPartner {
            id: "partner-classlink".to_string(),
            name: "ClassLink App".to_string(),
            logo_url: None,
            protocol: SsoProtocol::ClassLinkCompat,
            enabled: true,
            source: SsoPartnerSource::Toml,
            tenant_id: None,
            roles: vec![],
            saml_entity_id: None,
            saml_acs_url: None,
            oidc_client_id: Some("classlink-client-1".to_string()),
            oidc_client_secret: Some("secret".to_string()),
            oidc_redirect_uris: vec!["https://classlink-app.example.com/callback".to_string()],
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
                    .uri("/launch/partner-classlink")
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
        assert!(location.contains("/oauth2/v2/auth"));
        assert!(location.contains("classlink-client-1"));
    }

    // -- Teacher Dashboard Tests --

    use chalk_core::db::repository::{ClassRepository, CourseRepository, EnrollmentRepository};
    use chalk_core::models::class::Class;
    use chalk_core::models::common::{ClassType, EnrollmentRole};
    use chalk_core::models::course::Course;
    use chalk_core::models::enrollment::Enrollment;

    async fn ensure_org_and_course(repo: &SqliteRepository) {
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
        let _ = repo.upsert_org(&org).await;

        let course = Course {
            sourced_id: "course-1".to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            title: "Test Course".to_string(),
            school_year: None,
            course_code: None,
            org: "org-1".to_string(),
            grades: vec![],
            subjects: vec![],
        };
        let _ = repo.upsert_course(&course).await;
    }

    async fn insert_teacher(repo: &SqliteRepository) -> User {
        ensure_org_and_course(repo).await;

        let user = User {
            sourced_id: "teacher-1".to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            username: "msmith".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Mary".to_string(),
            family_name: "Smith".to_string(),
            middle_name: None,
            role: RoleType::Teacher,
            identifier: Some("T001".to_string()),
            email: Some("msmith@school.edu".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-1".to_string()],
            grades: vec![],
        };
        repo.upsert_user(&user).await.unwrap();
        user
    }

    async fn insert_student(repo: &SqliteRepository, id: &str, username: &str) -> User {
        ensure_org_and_course(repo).await;
        let user = User {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            username: username.to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Student".to_string(),
            family_name: username.to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: Some(format!("S{}", id)),
            email: Some(format!("{}@school.edu", username)),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-1".to_string()],
            grades: vec!["09".to_string()],
        };
        repo.upsert_user(&user).await.unwrap();
        user
    }

    async fn insert_class(repo: &SqliteRepository, id: &str, title: &str) -> Class {
        ensure_org_and_course(repo).await;
        let class = Class {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            title: title.to_string(),
            class_code: Some(format!("{}-CODE", id)),
            class_type: ClassType::Homeroom,
            location: None,
            grades: vec![],
            subjects: vec![],
            course: "course-1".to_string(),
            school: "org-1".to_string(),
            terms: vec![],
            periods: vec![],
        };
        repo.upsert_class(&class).await.unwrap();
        class
    }

    async fn insert_enrollment(
        repo: &SqliteRepository,
        id: &str,
        user_id: &str,
        class_id: &str,
        role: EnrollmentRole,
    ) {
        let enrollment = Enrollment {
            sourced_id: id.to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            user: user_id.to_string(),
            class: class_id.to_string(),
            school: "org-1".to_string(),
            role,
            primary: Some(true),
            begin_date: None,
            end_date: None,
        };
        repo.upsert_enrollment(&enrollment).await.unwrap();
    }

    #[tokio::test]
    async fn my_classes_redirects_without_session() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/my-classes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[tokio::test]
    async fn my_classes_rejects_non_teacher() {
        let repo = test_repo().await;
        insert_test_user(&repo).await; // student role
        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/my-classes")
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
        assert!(String::from_utf8_lossy(&body).contains("Only teachers"));
    }

    #[tokio::test]
    async fn my_classes_shows_teacher_classes() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_class(&repo, "class-2", "Science 201").await;
        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-t2",
            "teacher-1",
            "class-2",
            EnrollmentRole::Teacher,
        )
        .await;
        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/my-classes")
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
        assert!(body_str.contains("Math 101"));
        assert!(body_str.contains("Science 201"));
    }

    #[tokio::test]
    async fn class_roster_shows_students() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_student(&repo, "student-1", "alice").await;
        insert_student(&repo, "student-2", "bob").await;
        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s1",
            "student-1",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s2",
            "student-2",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;
        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/my-classes/class-1")
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
        assert!(body_str.contains("alice"));
        assert!(body_str.contains("bob"));
        assert!(body_str.contains("Math 101"));
    }

    #[tokio::test]
    async fn class_roster_denies_cross_class_access() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_class(&repo, "class-2", "Science 201").await;
        // Teacher only enrolled in class-1
        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/my-classes/class-2")
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
        assert!(String::from_utf8_lossy(&body).contains("not enrolled as a teacher"));
    }

    #[tokio::test]
    async fn reset_password_auto_generates() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_student(&repo, "student-1", "alice").await;
        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s1",
            "student-1",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;
        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/my-classes/class-1/reset-password/student-1")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(""))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("Student alice"));
        // Password should be present in the response
        assert!(body_str.len() > 10);
    }

    #[tokio::test]
    async fn reset_password_custom() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_student(&repo, "student-1", "alice").await;
        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s1",
            "student-1",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;
        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/my-classes/class-1/reset-password/student-1")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("custom_password=MyNewPass123"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("MyNewPass123"));
    }

    #[tokio::test]
    async fn reset_password_denies_cross_class() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_class(&repo, "class-2", "Science 201").await;
        insert_student(&repo, "student-1", "alice").await;
        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s1",
            "student-1",
            "class-2",
            EnrollmentRole::Student,
        )
        .await;
        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/my-classes/class-1/reset-password/student-1")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(""))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("not enrolled in this class"));
    }

    #[tokio::test]
    async fn generate_badge_returns_html_with_img() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_student(&repo, "student-1", "alice").await;
        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s1",
            "student-1",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;
        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/my-classes/class-1/generate-badge/student-1")
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
        assert!(body_str.contains("<img"));
        assert!(body_str.contains("data:image/png;base64,"));
        assert!(body_str.contains("QR Badge Generated"));
    }

    #[tokio::test]
    async fn my_classes_filters_inactive_enrollments() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_class(&repo, "class-2", "Science 201").await;
        // Active enrollment
        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        // Inactive enrollment (ToBeDeleted)
        let inactive_enrollment = Enrollment {
            sourced_id: "enr-t2".to_string(),
            status: Status::ToBeDeleted,
            date_last_modified: Utc::now(),
            metadata: None,
            user: "teacher-1".to_string(),
            class: "class-2".to_string(),
            school: "org-1".to_string(),
            role: EnrollmentRole::Teacher,
            primary: Some(true),
            begin_date: None,
            end_date: None,
        };
        repo.upsert_enrollment(&inactive_enrollment).await.unwrap();

        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/my-classes")
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
        assert!(body_str.contains("Math 101"));
        assert!(!body_str.contains("Science 201"));
    }

    #[tokio::test]
    async fn class_roster_filters_inactive_students() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        insert_student(&repo, "student-1", "alice").await;

        // Insert a disabled student
        let disabled_student = User {
            sourced_id: "student-2".to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            username: "bob".to_string(),
            user_ids: vec![],
            enabled_user: false,
            given_name: "Student".to_string(),
            family_name: "bob".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: Some("Sstudent-2".to_string()),
            email: Some("bob@school.edu".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-1".to_string()],
            grades: vec!["09".to_string()],
        };
        repo.upsert_user(&disabled_student).await.unwrap();

        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s1",
            "student-1",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s2",
            "student-2",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;

        let session_id = insert_portal_session(&repo, "teacher-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/my-classes/class-1")
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
        assert!(body_str.contains("alice"));
        assert!(!body_str.contains("bob"));
    }

    #[tokio::test]
    async fn reset_password_auto_generate_error_shows_message() {
        let repo = test_repo().await;
        insert_teacher(&repo).await;
        insert_class(&repo, "class-1", "Math 101").await;
        // Create student without identifier (needed for {identifier} pattern)
        let student = User {
            sourced_id: "student-noident".to_string(),
            status: Status::Active,
            date_last_modified: Utc::now(),
            metadata: None,
            username: "charlie".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "Student".to_string(),
            family_name: "Charlie".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("charlie@school.edu".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-1".to_string()],
            grades: vec!["09".to_string()],
        };
        repo.upsert_user(&student).await.unwrap();

        insert_enrollment(
            &repo,
            "enr-t1",
            "teacher-1",
            "class-1",
            EnrollmentRole::Teacher,
        )
        .await;
        insert_enrollment(
            &repo,
            "enr-s1",
            "student-noident",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;

        let session_id = insert_portal_session(&repo, "teacher-1").await;
        // Use a pattern that requires birthYear (which needs demographics)
        let mut config = test_config();
        config.idp.default_password_pattern = Some("{birthYear}".to_string());
        let state = Arc::new(crate::routes::IdpState {
            repo: Arc::new(repo),
            config,
            partners: Vec::new(),
            signing_key: None,
            signing_cert: None,
        });
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/my-classes/class-1/reset-password/student-noident")
                    .header("cookie", format!("chalk_portal={}", session_id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(""))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("Auto-generate failed"));
        assert!(body_str.contains("custom password"));
    }

    #[tokio::test]
    async fn generate_badge_denies_non_teacher() {
        let repo = test_repo().await;
        insert_test_user(&repo).await; // student role
        insert_class(&repo, "class-1", "Math 101").await;
        insert_student(&repo, "student-1", "alice").await;
        insert_enrollment(
            &repo,
            "enr-s1",
            "student-1",
            "class-1",
            EnrollmentRole::Student,
        )
        .await;
        let session_id = insert_portal_session(&repo, "user-1").await;
        let state = test_state(repo);
        let app = test_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/my-classes/class-1/generate-badge/student-1")
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
        assert!(String::from_utf8_lossy(&body).contains("Only teachers"));
    }

    #[test]
    fn error_html_escapes_special_characters() {
        let response = error_html("<script>alert('xss')</script> & \"more\"");
        let body = response.into_body();
        let body_bytes = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(axum::body::to_bytes(body, usize::MAX))
            .unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);

        // Should NOT contain raw HTML tags
        assert!(!body_str.contains("<script>"));
        assert!(!body_str.contains("</script>"));

        // Should contain escaped versions
        assert!(body_str.contains("&lt;script&gt;"));
        assert!(body_str.contains("&lt;/script&gt;"));
        assert!(body_str.contains("alert(&#x27;xss&#x27;)"));
        assert!(body_str.contains("&amp;"));
        assert!(body_str.contains("&quot;more&quot;"));
    }
}
