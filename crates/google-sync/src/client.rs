//! Typed reqwest wrapper for Google Admin Directory API.
//!
//! Every request runs through [`RetryExecutor`], which resolves a fresh bearer
//! token per attempt, paces requests through one shared token bucket, and
//! classifies failures on Google's `reason` field rather than the HTTP status.
//! The client therefore never holds a token string of its own — a sync run
//! longer than a token lifetime recovers instead of 401ing.

use std::sync::Arc;

use chalk_core::error::{ChalkError, Result};
use serde::de::DeserializeOwned;

use crate::backoff::{GoogleErrorClass, OperationKind, RateLimiter, RetryExecutor, RetryPolicy};
use crate::models::{GoogleOrgUnit, GoogleOrgUnitList, GoogleUser, GoogleUserList};
use crate::token::{StaticTokenProvider, TokenProvider};

const GOOGLE_ADMIN_API_BASE: &str = "https://admin.googleapis.com";

/// HTTP client for Google Admin Directory API operations.
#[derive(Debug, Clone)]
pub struct GoogleAdminClient {
    http: reqwest::Client,
    base_url: String,
    retry: RetryExecutor,
    customer_id: String,
}

impl GoogleAdminClient {
    /// Create a new client with a fixed auth token and customer ID.
    ///
    /// Retained for callers that already hold a token. The token cannot be
    /// refreshed, so long runs should prefer
    /// [`GoogleAdminClient::with_token_provider`] over a
    /// [`StaticTokenProvider`].
    pub fn new(auth_token: &str, customer_id: &str) -> Self {
        Self::with_token_provider(Arc::new(StaticTokenProvider::new(auth_token)), customer_id)
    }

    /// Create a client that resolves its bearer token through `auth` on every
    /// request, refreshing across the hour boundary of a long fleet walk.
    pub fn with_token_provider(auth: Arc<dyn TokenProvider>, customer_id: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: GOOGLE_ADMIN_API_BASE.to_string(),
            retry: RetryExecutor::new(auth),
            customer_id: customer_id.to_string(),
        }
    }

    /// Override the base URL (for testing with wiremock).
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Override the retry policy — used by tests to drive the retry paths
    /// without sleeping.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry = self.retry.with_policy(policy);
        self
    }

    /// Override the shared client-side rate limiter.
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.retry = self.retry.with_rate_limiter(limiter);
        self
    }

    /// The token provider backing this client.
    pub fn auth(&self) -> &Arc<dyn TokenProvider> {
        self.retry.auth()
    }

    /// Number of throttle events observed by this client so far.
    pub fn throttle_events(&self) -> u64 {
        self.retry.throttle_events()
    }

    fn users_url(&self) -> String {
        format!("{}/admin/directory/v1/users", self.base_url)
    }

    fn user_url(&self, email: &str) -> String {
        format!("{}/admin/directory/v1/users/{}", self.base_url, email)
    }

    fn orgunits_url(&self) -> String {
        format!(
            "{}/admin/directory/v1/customer/{}/orgunits",
            self.base_url, self.customer_id
        )
    }

    /// Deserialize a successful response body, naming the operation on failure.
    async fn parse_json<T: DeserializeOwned>(
        resp: reqwest::Response,
        operation: &str,
    ) -> Result<T> {
        resp.json::<T>()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("{operation} parse failed: {e}")))
    }

    /// Create a new Google Workspace user.
    pub async fn create_user(&self, user: &GoogleUser) -> Result<GoogleUser> {
        let url = self.users_url();
        let resp = self
            .retry
            .execute(OperationKind::Write, "create user", || {
                self.http.post(&url).json(user)
            })
            .await?;
        Self::parse_json(resp, "create user").await
    }

    /// Update an existing Google Workspace user by email.
    pub async fn update_user(&self, email: &str, user: &GoogleUser) -> Result<GoogleUser> {
        let url = self.user_url(email);
        let resp = self
            .retry
            .execute(OperationKind::Write, "update user", || {
                self.http.put(&url).json(user)
            })
            .await?;
        Self::parse_json(resp, "update user").await
    }

    /// Get a Google Workspace user by email. Returns None if 404.
    pub async fn get_user(&self, email: &str) -> Result<Option<GoogleUser>> {
        let url = self.user_url(email);
        let resp = self
            .retry
            .execute(OperationKind::Read, "get user", || self.http.get(&url))
            .await;

        match resp {
            Ok(resp) => Ok(Some(Self::parse_json(resp, "get user").await?)),
            Err(e) if e.class == GoogleErrorClass::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List Google Workspace users with optional pagination.
    pub async fn list_users(&self, page_token: Option<&str>) -> Result<GoogleUserList> {
        let url = self.users_url();
        let resp = self
            .retry
            .execute(OperationKind::Read, "list users", || {
                let mut req = self
                    .http
                    .get(&url)
                    .query(&[("customer", &self.customer_id)]);
                if let Some(token) = page_token {
                    req = req.query(&[("pageToken", token)]);
                }
                req
            })
            .await?;
        Self::parse_json(resp, "list users").await
    }

    /// Suspend a Google Workspace user by email.
    pub async fn suspend_user(&self, email: &str) -> Result<()> {
        let url = self.user_url(email);
        let body = serde_json::json!({ "suspended": true });
        self.retry
            .execute(OperationKind::Write, "suspend user", || {
                self.http.put(&url).json(&body)
            })
            .await?;
        Ok(())
    }

    /// List all Organizational Units for this customer.
    pub async fn list_org_units(&self) -> Result<Vec<GoogleOrgUnit>> {
        let url = self.orgunits_url();
        let resp = self
            .retry
            .execute(OperationKind::Read, "list OUs", || {
                self.http.get(&url).query(&[("type", "all")])
            })
            .await?;
        let list: GoogleOrgUnitList = Self::parse_json(resp, "list OUs").await?;
        Ok(list.organization_units.unwrap_or_default())
    }

    /// Create a new Organizational Unit.
    pub async fn create_org_unit(&self, ou: &GoogleOrgUnit) -> Result<GoogleOrgUnit> {
        let url = self.orgunits_url();
        let resp = self
            .retry
            .execute(OperationKind::Write, "create OU", || {
                self.http.post(&url).json(ou)
            })
            .await?;
        Self::parse_json(resp, "create OU").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::GoogleUserName;
    use crate::token::tests::CountingTokenProvider;
    use wiremock::matchers::{bearer_token, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Builds a client pointed at a mock server. The retry policy keeps the
    /// production attempt counts but drops every delay to zero, so tests that
    /// exercise the retry paths finish immediately instead of sleeping through
    /// the real 1s→32s schedule.
    async fn setup() -> (MockServer, GoogleAdminClient) {
        let server = MockServer::start().await;
        let client = GoogleAdminClient::new("test-token", "C12345")
            .with_base_url(&server.uri())
            .with_retry_policy(RetryPolicy::test_fast())
            .with_rate_limiter(RateLimiter::unlimited());
        (server, client)
    }

    #[tokio::test]
    async fn create_user_success() {
        let (server, client) = setup().await;

        let response_body = serde_json::json!({
            "primaryEmail": "jdoe@school.edu",
            "name": {"givenName": "John", "familyName": "Doe"},
            "id": "new-id-123"
        });

        Mock::given(method("POST"))
            .and(path("/admin/directory/v1/users"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let user = GoogleUser {
            primary_email: "jdoe@school.edu".to_string(),
            name: GoogleUserName {
                given_name: "John".to_string(),
                family_name: "Doe".to_string(),
            },
            suspended: None,
            org_unit_path: Some("/Students".to_string()),
            id: None,
            password: Some("temp123".to_string()),
            change_password_at_next_login: Some(true),
        };

        let result = client.create_user(&user).await.unwrap();
        assert_eq!(result.primary_email, "jdoe@school.edu");
        assert_eq!(result.id.as_deref(), Some("new-id-123"));
    }

    #[tokio::test]
    async fn get_user_found() {
        let (server, client) = setup().await;

        let response_body = serde_json::json!({
            "primaryEmail": "jdoe@school.edu",
            "name": {"givenName": "John", "familyName": "Doe"},
            "id": "123"
        });

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users/jdoe@school.edu"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let result = client.get_user("jdoe@school.edu").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().primary_email, "jdoe@school.edu");
    }

    #[tokio::test]
    async fn get_user_not_found() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users/nobody@school.edu"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let result = client.get_user("nobody@school.edu").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_user_server_error() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users/error@school.edu"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let result = client.get_user("error@school.edu").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("500"));
    }

    #[tokio::test]
    async fn list_users_success() {
        let (server, client) = setup().await;

        let response_body = serde_json::json!({
            "users": [
                {
                    "primaryEmail": "a@school.edu",
                    "name": {"givenName": "A", "familyName": "User"}
                },
                {
                    "primaryEmail": "b@school.edu",
                    "name": {"givenName": "B", "familyName": "User"}
                }
            ],
            "nextPageToken": "page2"
        });

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users"))
            .and(query_param("customer", "C12345"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let result = client.list_users(None).await.unwrap();
        assert_eq!(result.users.as_ref().unwrap().len(), 2);
        assert_eq!(result.next_page_token.as_deref(), Some("page2"));
    }

    #[tokio::test]
    async fn suspend_user_success() {
        let (server, client) = setup().await;

        let response_body = serde_json::json!({
            "primaryEmail": "jdoe@school.edu",
            "name": {"givenName": "John", "familyName": "Doe"},
            "suspended": true
        });

        Mock::given(method("PUT"))
            .and(path("/admin/directory/v1/users/jdoe@school.edu"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        client.suspend_user("jdoe@school.edu").await.unwrap();
    }

    #[tokio::test]
    async fn list_org_units_success() {
        let (server, client) = setup().await;

        let response_body = serde_json::json!({
            "organizationUnits": [
                {
                    "name": "Students",
                    "orgUnitPath": "/Students",
                    "parentOrgUnitPath": "/",
                    "orgUnitId": "ou-1"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/customer/C12345/orgunits"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let result = client.list_org_units().await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "Students");
    }

    #[tokio::test]
    async fn create_org_unit_success() {
        let (server, client) = setup().await;

        let response_body = serde_json::json!({
            "name": "Grade 9",
            "orgUnitPath": "/Students/HS/09",
            "parentOrgUnitPath": "/Students/HS",
            "orgUnitId": "ou-new"
        });

        Mock::given(method("POST"))
            .and(path("/admin/directory/v1/customer/C12345/orgunits"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let ou = GoogleOrgUnit {
            name: "Grade 9".to_string(),
            org_unit_path: "/Students/HS/09".to_string(),
            parent_org_unit_path: Some("/Students/HS".to_string()),
            org_unit_id: None,
        };

        let result = client.create_org_unit(&ou).await.unwrap();
        assert_eq!(result.org_unit_id.as_deref(), Some("ou-new"));
    }

    #[tokio::test]
    async fn create_user_conflict_error() {
        let (server, client) = setup().await;

        Mock::given(method("POST"))
            .and(path("/admin/directory/v1/users"))
            .respond_with(ResponseTemplate::new(409).set_body_string("Entity already exists"))
            .mount(&server)
            .await;

        let user = GoogleUser {
            primary_email: "existing@school.edu".to_string(),
            name: GoogleUserName {
                given_name: "Existing".to_string(),
                family_name: "User".to_string(),
            },
            suspended: None,
            org_unit_path: None,
            id: None,
            password: None,
            change_password_at_next_login: None,
        };

        let result = client.create_user(&user).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("409"));
    }

    #[tokio::test]
    async fn update_user_success() {
        let (server, client) = setup().await;

        let response_body = serde_json::json!({
            "primaryEmail": "jdoe@school.edu",
            "name": {"givenName": "Jonathan", "familyName": "Doe"},
            "orgUnitPath": "/Students/HS/10"
        });

        Mock::given(method("PUT"))
            .and(path("/admin/directory/v1/users/jdoe@school.edu"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&server)
            .await;

        let user = GoogleUser {
            primary_email: "jdoe@school.edu".to_string(),
            name: GoogleUserName {
                given_name: "Jonathan".to_string(),
                family_name: "Doe".to_string(),
            },
            suspended: None,
            org_unit_path: Some("/Students/HS/10".to_string()),
            id: None,
            password: None,
            change_password_at_next_login: None,
        };

        let result = client.update_user("jdoe@school.edu", &user).await.unwrap();
        assert_eq!(result.name.given_name, "Jonathan");
    }

    #[tokio::test]
    async fn new_still_sends_the_given_static_token() {
        // The compatibility constructor must behave exactly as it did before
        // the TokenProvider seam existed: one fixed bearer token, no refresh.
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users/x@school.edu"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "primaryEmail": "x@school.edu",
                "name": {"givenName": "X", "familyName": "Y"}
            })))
            .mount(&server)
            .await;

        assert!(client.get_user("x@school.edu").await.unwrap().is_some());
        assert_eq!(client.auth().token().await.unwrap(), "test-token");
        client.auth().invalidate().await;
        assert_eq!(client.auth().token().await.unwrap(), "test-token");
    }

    #[tokio::test]
    async fn token_is_resolved_per_request_not_cached_in_the_client() {
        // The live bug this seam fixes: a client that copied the token at
        // construction could never pick up a refreshed one.
        let server = MockServer::start().await;
        let auth = Arc::new(CountingTokenProvider::default());
        let client = GoogleAdminClient::with_token_provider(auth.clone(), "C12345")
            .with_base_url(&server.uri())
            .with_retry_policy(RetryPolicy::test_fast())
            .with_rate_limiter(RateLimiter::unlimited());

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/customer/C12345/orgunits"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        client.list_org_units().await.unwrap();
        client.list_org_units().await.unwrap();

        assert_eq!(
            auth.tokens_issued.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[tokio::test]
    async fn read_retries_a_403_rate_limit_then_succeeds() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": {"code": 403, "message": "rate limit",
                          "errors": [{"domain": "usageLimits", "reason": "rateLimitExceeded"}]}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"users": []})),
            )
            .mount(&server)
            .await;

        let result = client.list_users(None).await.unwrap();
        assert!(result.users.unwrap_or_default().is_empty());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        assert_eq!(client.throttle_events(), 1);
    }

    #[tokio::test]
    async fn read_does_not_retry_a_403_permission_failure() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": {"code": 403, "message": "Not Authorized to access this resource/api",
                          "errors": [{"domain": "global", "reason": "forbidden"}]}
            })))
            .mount(&server)
            .await;

        let err = client.list_users(None).await.unwrap_err().to_string();
        assert!(err.contains("permission denied"), "{err}");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn write_does_not_retry_a_500() {
        let (server, client) = setup().await;

        Mock::given(method("POST"))
            .and(path("/admin/directory/v1/users"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let user = GoogleUser {
            primary_email: "a@school.edu".to_string(),
            name: GoogleUserName {
                given_name: "A".to_string(),
                family_name: "B".to_string(),
            },
            suspended: None,
            org_unit_path: None,
            id: None,
            password: None,
            change_password_at_next_login: None,
        };

        assert!(client.create_user(&user).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn list_org_units_empty() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/customer/C12345/orgunits"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let result = client.list_org_units().await.unwrap();
        assert!(result.is_empty());
    }
}
