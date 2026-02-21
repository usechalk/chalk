use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::error::{ChalkError, Result};

/// OAuth token response from a OneRoster-compliant SIS.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

/// Shared HTTP client for OneRoster 1.1 APIs with OAuth 2.0 client credentials authentication.
///
/// This client handles authentication and paginated data fetching for any SIS
/// that implements the OneRoster 1.1 REST API standard.
pub struct OneRosterClient {
    base_url: String,
    token_url: String,
    client_id: String,
    client_secret: String,
    http: Client,
    access_token: RwLock<Option<String>>,
}

impl OneRosterClient {
    pub fn new(base_url: &str, token_url: &str, client_id: &str, client_secret: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token_url: token_url.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            http: Client::new(),
            access_token: RwLock::new(None),
        }
    }

    /// Create a client with a custom reqwest::Client (useful for testing).
    pub fn with_http_client(
        base_url: &str,
        token_url: &str,
        client_id: &str,
        client_secret: &str,
        http: Client,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token_url: token_url.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            http,
            access_token: RwLock::new(None),
        }
    }

    /// Authenticate with the OAuth 2.0 endpoint using client credentials.
    pub async fn authenticate(&self) -> Result<()> {
        debug!(url = %self.token_url, "Authenticating with OneRoster API");

        let response = self
            .http
            .post(&self.token_url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(status = %status, body = %body, "Authentication failed");
            return Err(ChalkError::Sync(format!(
                "OneRoster authentication failed with status {status}: {body}"
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| ChalkError::Sync(format!("Failed to parse token response: {e}")))?;

        let mut token = self.access_token.write().await;
        *token = Some(token_response.access_token);
        debug!("OneRoster authentication successful");

        Ok(())
    }

    /// Fetch all pages of a paginated OneRoster endpoint.
    ///
    /// The `endpoint` is the relative path (e.g., "/orgs").
    /// The `wrapper_key` is the JSON key that wraps the results (e.g., "orgs").
    /// Returns a Vec of the deserialized response type for each page.
    pub async fn get_all<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        wrapper_key: &str,
    ) -> Result<Vec<T>> {
        let token_guard = self.access_token.read().await;
        let token = token_guard.as_ref().ok_or_else(|| {
            ChalkError::Sync("Not authenticated. Call authenticate() first.".to_string())
        })?;
        let bearer = format!("Bearer {token}");
        drop(token_guard);

        let mut results: Vec<T> = Vec::new();
        let mut offset: u64 = 0;
        let limit: u64 = 100;

        loop {
            let url = format!("{}{endpoint}?limit={limit}&offset={offset}", self.base_url);
            debug!(url = %url, "Fetching page");

            let response = self
                .http
                .get(&url)
                .header("Authorization", &bearer)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                warn!(status = %status, endpoint = %endpoint, "API request failed");
                return Err(ChalkError::Sync(format!(
                    "OneRoster API request to {endpoint} failed with status {status}: {body}"
                )));
            }

            let body = response.text().await?;

            let value: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| ChalkError::Sync(format!("Failed to parse API response: {e}")))?;

            let arr = value.get(wrapper_key).and_then(|v| v.as_array());
            let page_count = arr.map_or(0, |a| a.len());

            if page_count == 0 {
                debug!(endpoint = %endpoint, "No more results, pagination complete");
                break;
            }

            let page: T = serde_json::from_value(value).map_err(|e| {
                ChalkError::Sync(format!(
                    "Failed to deserialize response for {endpoint}: {e}"
                ))
            })?;
            results.push(page);

            if (page_count as u64) < limit {
                debug!(endpoint = %endpoint, page_count, "Last page received");
                break;
            }

            offset += limit;
        }

        Ok(results)
    }

    /// Test the connection by authenticating and fetching the first page of orgs.
    pub async fn test_connection(&self) -> Result<()> {
        self.authenticate().await?;
        // Fetch first page of orgs with limit=1 to validate API access
        let token_guard = self.access_token.read().await;
        let token = token_guard
            .as_ref()
            .ok_or_else(|| ChalkError::Sync("Not authenticated".to_string()))?;
        let bearer = format!("Bearer {token}");
        drop(token_guard);

        let url = format!("{}/orgs?limit=1", self.base_url);
        let response = self
            .http
            .get(&url)
            .header("Authorization", &bearer)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ChalkError::Sync(format!(
                "Connection test failed with status {status}: {body}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn authenticate_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-token-123",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let token_url = format!("{}/oauth/token", mock_server.uri());
        let client =
            OneRosterClient::new(&mock_server.uri(), &token_url, "client_id", "client_secret");
        client.authenticate().await.unwrap();

        let token = client.access_token.read().await;
        assert_eq!(token.as_deref(), Some("test-token-123"));
    }

    #[tokio::test]
    async fn authenticate_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&mock_server)
            .await;

        let token_url = format!("{}/oauth/token", mock_server.uri());
        let client = OneRosterClient::new(&mock_server.uri(), &token_url, "bad_id", "bad_secret");
        let result = client.authenticate().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("authentication failed"));
    }

    #[tokio::test]
    async fn get_all_single_page() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-token",
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/orgs"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "orgs": [
                    {
                        "sourcedId": "org-001",
                        "status": "active",
                        "dateLastModified": "2025-01-15T12:00:00Z",
                        "name": "Test District",
                        "type": "district"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let token_url = format!("{}/oauth/token", mock_server.uri());
        let client = OneRosterClient::new(&mock_server.uri(), &token_url, "id", "secret");
        client.authenticate().await.unwrap();

        use crate::connectors::powerschool::models::OrgsResponse;
        let pages: Vec<OrgsResponse> = client.get_all("/orgs", "orgs").await.unwrap();

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].orgs.len(), 1);
        assert_eq!(pages[0].orgs[0].sourced_id, "org-001");
    }

    #[tokio::test]
    async fn get_all_without_auth_fails() {
        let client = OneRosterClient::new(
            "http://localhost:1234",
            "http://localhost:1234/oauth/token",
            "id",
            "secret",
        );

        use crate::connectors::powerschool::models::OrgsResponse;
        let result: Result<Vec<OrgsResponse>> = client.get_all("/orgs", "orgs").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Not authenticated"));
    }

    #[tokio::test]
    async fn test_connection_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-token",
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/orgs"))
            .and(query_param("limit", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "orgs": [{"sourcedId": "org-001", "status": "active", "dateLastModified": "2025-01-15T12:00:00Z", "name": "Test", "type": "district"}]
            })))
            .mount(&mock_server)
            .await;

        let token_url = format!("{}/oauth/token", mock_server.uri());
        let client = OneRosterClient::new(&mock_server.uri(), &token_url, "id", "secret");
        client.test_connection().await.unwrap();
    }

    #[tokio::test]
    async fn token_response_deserialize() {
        let json = r#"{"access_token":"abc123","token_type":"Bearer","expires_in":3600}"#;
        let token: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(token.access_token, "abc123");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, Some(3600));
    }

    #[tokio::test]
    async fn token_response_without_expires() {
        let json = r#"{"access_token":"abc123","token_type":"Bearer"}"#;
        let token: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(token.access_token, "abc123");
        assert_eq!(token.expires_in, None);
    }
}
