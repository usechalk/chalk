//! Typed reqwest wrapper for Google Admin Directory API.

use chalk_core::error::{ChalkError, Result};
use reqwest::StatusCode;

use crate::models::{GoogleOrgUnit, GoogleOrgUnitList, GoogleUser, GoogleUserList};

const GOOGLE_ADMIN_API_BASE: &str = "https://admin.googleapis.com";

/// HTTP client for Google Admin Directory API operations.
pub struct GoogleAdminClient {
    http: reqwest::Client,
    base_url: String,
    auth_token: String,
    customer_id: String,
}

impl GoogleAdminClient {
    /// Create a new client with the given auth token and customer ID.
    pub fn new(auth_token: &str, customer_id: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: GOOGLE_ADMIN_API_BASE.to_string(),
            auth_token: auth_token.to_string(),
            customer_id: customer_id.to_string(),
        }
    }

    /// Override the base URL (for testing with wiremock).
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
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

    /// Create a new Google Workspace user.
    pub async fn create_user(&self, user: &GoogleUser) -> Result<GoogleUser> {
        let resp = self
            .http
            .post(self.users_url())
            .bearer_auth(&self.auth_token)
            .json(user)
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("create user request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "create user failed ({status}): {body}"
            )));
        }

        resp.json::<GoogleUser>()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("create user parse failed: {e}")))
    }

    /// Update an existing Google Workspace user by email.
    pub async fn update_user(&self, email: &str, user: &GoogleUser) -> Result<GoogleUser> {
        let resp = self
            .http
            .put(self.user_url(email))
            .bearer_auth(&self.auth_token)
            .json(user)
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("update user request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "update user failed ({status}): {body}"
            )));
        }

        resp.json::<GoogleUser>()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("update user parse failed: {e}")))
    }

    /// Get a Google Workspace user by email. Returns None if 404.
    pub async fn get_user(&self, email: &str) -> Result<Option<GoogleUser>> {
        let resp = self
            .http
            .get(self.user_url(email))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("get user request failed: {e}")))?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "get user failed ({status}): {body}"
            )));
        }

        let user = resp
            .json::<GoogleUser>()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("get user parse failed: {e}")))?;
        Ok(Some(user))
    }

    /// List Google Workspace users with optional pagination.
    pub async fn list_users(&self, page_token: Option<&str>) -> Result<GoogleUserList> {
        let mut req = self
            .http
            .get(self.users_url())
            .bearer_auth(&self.auth_token)
            .query(&[("customer", &self.customer_id)]);

        if let Some(token) = page_token {
            req = req.query(&[("pageToken", token)]);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("list users request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "list users failed ({status}): {body}"
            )));
        }

        resp.json::<GoogleUserList>()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("list users parse failed: {e}")))
    }

    /// Suspend a Google Workspace user by email.
    pub async fn suspend_user(&self, email: &str) -> Result<()> {
        let body = serde_json::json!({ "suspended": true });
        let resp = self
            .http
            .put(self.user_url(email))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("suspend user request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "suspend user failed ({status}): {body}"
            )));
        }

        Ok(())
    }

    /// List all Organizational Units for this customer.
    pub async fn list_org_units(&self) -> Result<Vec<GoogleOrgUnit>> {
        let resp = self
            .http
            .get(self.orgunits_url())
            .bearer_auth(&self.auth_token)
            .query(&[("type", "all")])
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("list OUs request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "list OUs failed ({status}): {body}"
            )));
        }

        let list = resp
            .json::<GoogleOrgUnitList>()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("list OUs parse failed: {e}")))?;
        Ok(list.organization_units.unwrap_or_default())
    }

    /// Create a new Organizational Unit.
    pub async fn create_org_unit(&self, ou: &GoogleOrgUnit) -> Result<GoogleOrgUnit> {
        let resp = self
            .http
            .post(self.orgunits_url())
            .bearer_auth(&self.auth_token)
            .json(ou)
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("create OU request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "create OU failed ({status}): {body}"
            )));
        }

        resp.json::<GoogleOrgUnit>()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("create OU parse failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::GoogleUserName;
    use wiremock::matchers::{bearer_token, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup() -> (MockServer, GoogleAdminClient) {
        let server = MockServer::start().await;
        let client = GoogleAdminClient::new("test-token", "C12345").with_base_url(&server.uri());
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
