//! OneRoster 1.1 REST API endpoints.
//!
//! Provides JSON API endpoints that wrap database queries in the standard
//! OneRoster JSON envelope format: `{ "<entityType>": [ ... ] }` for
//! collections and `{ "<entityType>": { ... } }` for single entities.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};

use chalk_core::db::repository::{
    AcademicSessionRepository, ClassRepository, CourseRepository, DemographicsRepository,
    EnrollmentRepository, OrgRepository, UserRepository,
};
use chalk_core::models::sync::UserFilter;

use crate::AppState;

/// Build the OneRoster API sub-router.
///
/// All routes are mounted under `/api/oneroster/v1p1` by the parent router.
pub fn oneroster_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/orgs", get(list_orgs))
        .route("/orgs/:id", get(get_org))
        .route("/academicSessions", get(list_academic_sessions))
        .route("/academicSessions/:id", get(get_academic_session))
        .route("/users", get(list_users))
        .route("/users/:id", get(get_user))
        .route("/courses", get(list_courses))
        .route("/courses/:id", get(get_course))
        .route("/classes", get(list_classes))
        .route("/classes/:id", get(get_class))
        .route("/enrollments", get(list_enrollments))
        .route("/enrollments/:id", get(get_enrollment))
        .route("/demographics", get(list_demographics))
        .route("/demographics/:id", get(get_demographics))
}

fn envelope(key: &str, value: Value) -> Value {
    json!({ key: value })
}

fn not_found(entity_type: &str, id: &str) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": format!("{entity_type} with sourcedId '{id}' not found")
        })),
    )
}

// -- Orgs --

async fn list_orgs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.repo.list_orgs().await {
        Ok(orgs) => {
            let value = serde_json::to_value(&orgs).unwrap_or(Value::Array(vec![]));
            (StatusCode::OK, Json(envelope("orgs", value)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn get_org(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match state.repo.get_org(&id).await {
        Ok(Some(org)) => {
            let value = serde_json::to_value(&org).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("org", value))).into_response()
        }
        Ok(None) => not_found("org", &id).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// -- Academic Sessions --

async fn list_academic_sessions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.repo.list_academic_sessions().await {
        Ok(sessions) => {
            let value = serde_json::to_value(&sessions).unwrap_or(Value::Array(vec![]));
            (StatusCode::OK, Json(envelope("academicSessions", value)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn get_academic_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.repo.get_academic_session(&id).await {
        Ok(Some(session)) => {
            let value = serde_json::to_value(&session).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("academicSession", value))).into_response()
        }
        Ok(None) => not_found("academicSession", &id).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// -- Users --

async fn list_users(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let filter = UserFilter {
        role: None,
        org_sourced_id: None,
        grade: None,
    };
    match state.repo.list_users(&filter).await {
        Ok(users) => {
            let value = serde_json::to_value(&users).unwrap_or(Value::Array(vec![]));
            (StatusCode::OK, Json(envelope("users", value)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn get_user(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match state.repo.get_user(&id).await {
        Ok(Some(user)) => {
            let value = serde_json::to_value(&user).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("user", value))).into_response()
        }
        Ok(None) => not_found("user", &id).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// -- Courses --

async fn list_courses(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.repo.list_courses().await {
        Ok(courses) => {
            let value = serde_json::to_value(&courses).unwrap_or(Value::Array(vec![]));
            (StatusCode::OK, Json(envelope("courses", value)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn get_course(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.repo.get_course(&id).await {
        Ok(Some(course)) => {
            let value = serde_json::to_value(&course).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("course", value))).into_response()
        }
        Ok(None) => not_found("course", &id).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// -- Classes --

async fn list_classes(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.repo.list_classes().await {
        Ok(classes) => {
            let value = serde_json::to_value(&classes).unwrap_or(Value::Array(vec![]));
            (StatusCode::OK, Json(envelope("classes", value)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn get_class(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.repo.get_class(&id).await {
        Ok(Some(class)) => {
            let value = serde_json::to_value(&class).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("class", value))).into_response()
        }
        Ok(None) => not_found("class", &id).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// -- Enrollments --

async fn list_enrollments(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.repo.list_enrollments().await {
        Ok(enrollments) => {
            let value = serde_json::to_value(&enrollments).unwrap_or(Value::Array(vec![]));
            (StatusCode::OK, Json(envelope("enrollments", value)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn get_enrollment(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.repo.get_enrollment(&id).await {
        Ok(Some(enrollment)) => {
            let value = serde_json::to_value(&enrollment).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("enrollment", value))).into_response()
        }
        Ok(None) => not_found("enrollment", &id).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// -- Demographics --

async fn list_demographics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.repo.list_demographics().await {
        Ok(demographics) => {
            let value = serde_json::to_value(&demographics).unwrap_or(Value::Array(vec![]));
            (StatusCode::OK, Json(envelope("demographics", value)))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn get_demographics(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.repo.get_demographics(&id).await {
        Ok(Some(demo)) => {
            let value = serde_json::to_value(&demo).unwrap_or(Value::Null);
            (StatusCode::OK, Json(envelope("demographics", value))).into_response()
        }
        Ok(None) => not_found("demographics", &id).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn test_state() -> Arc<AppState> {
        let pool = chalk_core::db::DatabasePool::new_sqlite_memory()
            .await
            .unwrap();
        let repo = match pool {
            chalk_core::db::DatabasePool::Sqlite(p) => {
                chalk_core::db::sqlite::SqliteRepository::new(p)
            }
        };
        let config = chalk_core::config::ChalkConfig::generate_default();
        Arc::new(AppState { repo, config })
    }

    async fn get_json(response: axum::http::Response<Body>) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn api_router(state: Arc<AppState>) -> Router {
        Router::new()
            .nest("/api/oneroster/v1p1", oneroster_router())
            .with_state(state)
    }

    // -- List endpoints return empty arrays --

    #[tokio::test]
    async fn list_orgs_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["orgs"].is_array());
        assert_eq!(json["orgs"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_users_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["users"].is_array());
    }

    #[tokio::test]
    async fn list_courses_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/courses")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["courses"].is_array());
    }

    #[tokio::test]
    async fn list_classes_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/classes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["classes"].is_array());
    }

    #[tokio::test]
    async fn list_enrollments_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/enrollments")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["enrollments"].is_array());
    }

    #[tokio::test]
    async fn list_academic_sessions_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/academicSessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["academicSessions"].is_array());
    }

    #[tokio::test]
    async fn list_demographics_empty() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/demographics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert!(json["demographics"].is_array());
    }

    // -- 404 for missing entities --

    #[tokio::test]
    async fn get_org_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = get_json(response).await;
        assert!(json["error"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn get_user_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/users/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_course_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/courses/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_class_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/classes/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_enrollment_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/enrollments/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_academic_session_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/academicSessions/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_demographics_not_found() {
        let state = test_state().await;
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/demographics/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -- With data --

    #[tokio::test]
    async fn list_and_get_org_with_data() {
        let state = test_state().await;

        use chalk_core::models::common::{OrgType, Status};
        use chalk_core::models::org::Org;
        use chrono::{TimeZone, Utc};

        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Test District".to_string(),
            org_type: OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        };
        state.repo.upsert_org(&org).await.unwrap();

        let app = api_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert_eq!(json["orgs"].as_array().unwrap().len(), 1);
        assert_eq!(json["orgs"][0]["sourcedId"], "org-001");

        // Get single
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/orgs/org-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert_eq!(json["org"]["sourcedId"], "org-001");
        assert_eq!(json["org"]["name"], "Test District");
    }

    #[tokio::test]
    async fn list_and_get_user_with_data() {
        let state = test_state().await;

        use chalk_core::models::common::{OrgType, RoleType, Status};
        use chalk_core::models::org::Org;
        use chalk_core::models::user::User;
        use chrono::{TimeZone, Utc};

        let org = Org {
            sourced_id: "org-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            name: "Test District".to_string(),
            org_type: OrgType::District,
            identifier: None,
            parent: None,
            children: vec![],
        };
        state.repo.upsert_org(&org).await.unwrap();

        let user = User {
            sourced_id: "user-001".to_string(),
            status: Status::Active,
            date_last_modified: Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap(),
            metadata: None,
            username: "jdoe".to_string(),
            user_ids: vec![],
            enabled_user: true,
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            middle_name: None,
            role: RoleType::Student,
            identifier: None,
            email: Some("jdoe@example.com".to_string()),
            sms: None,
            phone: None,
            agents: vec![],
            orgs: vec!["org-001".to_string()],
            grades: vec!["09".to_string()],
        };
        state.repo.upsert_user(&user).await.unwrap();

        let app = api_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert_eq!(json["users"].as_array().unwrap().len(), 1);
        assert_eq!(json["users"][0]["username"], "jdoe");

        // Get single
        let app = api_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/oneroster/v1p1/users/user-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = get_json(response).await;
        assert_eq!(json["user"]["sourcedId"], "user-001");
        assert_eq!(json["user"]["givenName"], "John");
    }
}
