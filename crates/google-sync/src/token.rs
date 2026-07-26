//! Token provision for Google APIs.
//!
//! Every Google client in this crate obtains its bearer token through
//! [`TokenProvider`] rather than holding a `String` captured at construction
//! time. That seam exists for one concrete reason: a fleet walk over 20,000
//! ChromeOS devices takes longer than the one-hour lifetime of an access
//! token, and a client holding a copied token has no way to recover from the
//! resulting 401.
//!
//! [`GoogleTokenSource`] is the real implementation. It supports both
//! credential shapes we ship (service-account JWT assertion for self-hosted
//! deployments, OAuth refresh-token grant for hosted), caches the access token
//! until it is inside the expiry skew window, and collapses concurrent
//! refreshes into a single token exchange.
//!
//! [`StaticTokenProvider`] wraps a fixed string; it backs the
//! `GoogleAdminClient::new(token, customer)` compatibility constructor and
//! doubles as the trivial test double.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use chalk_core::error::{ChalkError, Result};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

/// Google's public OAuth2 token endpoint.
///
/// Held as an explicit field on [`GoogleTokenSource`] rather than being read
/// exclusively from the service-account key file: the OAuth refresh-token flow
/// has no key file, so without this the flow would have no seam for tests to
/// redirect the exchange at a mock server.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Read/write scope for ChromeOS device management.
pub const SCOPE_DEVICE_CHROMEOS: &str =
    "https://www.googleapis.com/auth/admin.directory.device.chromeos";

/// Read-only scope for ChromeOS device management. Requested until a tenant
/// explicitly enables write-back.
pub const SCOPE_DEVICE_CHROMEOS_READONLY: &str =
    "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly";

/// Read-only scope for the Organizational Unit tree.
pub const SCOPE_ORGUNIT_READONLY: &str =
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly";

/// Read-only scope for directory users.
pub const SCOPE_USER_READONLY: &str =
    "https://www.googleapis.com/auth/admin.directory.user.readonly";

/// The complete scope set the ChromeOS device sync requests.
///
/// Every entry is a `.readonly` variant. Device sync reads; it does not write.
/// Write-back will request its own scopes when it ships with its own
/// authorization review — do not widen this array to prepare for it.
pub const DEVICE_SYNC_READ_SCOPES: &[&str] = &[
    SCOPE_DEVICE_CHROMEOS_READONLY,
    SCOPE_ORGUNIT_READONLY,
    SCOPE_USER_READONLY,
];

/// How long before nominal expiry a cached token is treated as stale.
const DEFAULT_EXPIRY_SKEW_SECONDS: i64 = 60;

/// Lifetime of the signed JWT assertion sent to Google for the service-account
/// grant. Google rejects assertions with a lifetime over one hour.
const ASSERTION_LIFETIME_SECONDS: i64 = 3600;

/// Supplies bearer tokens to Google API clients.
///
/// Implementations are shared across cloned clients via `Arc`, so a single
/// token cache backs every request an operation makes.
#[async_trait]
pub trait TokenProvider: Send + Sync + fmt::Debug {
    /// Return a currently valid bearer token, refreshing it if the cached one
    /// is expired or inside the skew window.
    async fn token(&self) -> Result<String>;

    /// Drop any cached token so the next [`TokenProvider::token`] call performs
    /// a fresh exchange. Called once when Google rejects a request with 401.
    async fn invalidate(&self);
}

/// A [`TokenProvider`] over a fixed, externally obtained token.
///
/// Refreshing is impossible, so [`StaticTokenProvider::invalidate`] is a no-op
/// and callers see the same token again — which is exactly the pre-existing
/// behaviour of `GoogleAdminClient::new(token, customer)`.
#[derive(Debug, Clone)]
pub struct StaticTokenProvider {
    token: String,
}

impl StaticTokenProvider {
    /// Wrap a fixed bearer token.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

#[async_trait]
impl TokenProvider for StaticTokenProvider {
    async fn token(&self) -> Result<String> {
        Ok(self.token.clone())
    }

    async fn invalidate(&self) {}
}

/// A cached access token and the instant it stops being usable.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

impl CachedToken {
    fn is_fresh(&self, skew: Duration, now: DateTime<Utc>) -> bool {
        now + skew < self.expires_at
    }
}

/// The credential material a [`GoogleTokenSource`] exchanges for access tokens.
pub enum GoogleCredentials {
    /// Service-account JWT assertion with domain-wide delegation.
    ServiceAccount {
        /// Service account address (`client_email` in the JSON key).
        client_email: String,
        /// PEM-encoded RSA private key (`private_key` in the JSON key).
        private_key_pem: String,
        /// Workspace admin the service account impersonates.
        admin_email: String,
    },
    /// OAuth 2.0 refresh-token grant, used by hosted Chalk.
    OauthRefreshToken {
        /// OAuth client id of Chalk's Cloud project.
        client_id: String,
        /// OAuth client secret.
        client_secret: String,
        /// Long-lived refresh token issued at consent time.
        refresh_token: String,
    },
}

impl fmt::Debug for GoogleCredentials {
    /// Redacts every secret; these values end up in client `Debug` output and
    /// in turn in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceAccount {
                client_email,
                admin_email,
                ..
            } => f
                .debug_struct("ServiceAccount")
                .field("client_email", client_email)
                .field("private_key_pem", &"<redacted>")
                .field("admin_email", admin_email)
                .finish(),
            Self::OauthRefreshToken { client_id, .. } => f
                .debug_struct("OauthRefreshToken")
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .field("refresh_token", &"<redacted>")
                .finish(),
        }
    }
}

/// Shape of a Google service-account JSON key file.
///
/// `token_uri` is optional here: real keys always carry it, but the default is
/// well-known and a key without it should not be a hard failure.
#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: Option<String>,
}

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

/// Caching, self-refreshing [`TokenProvider`] over Google's token endpoint.
///
/// The hot path takes a read lock and returns a clone of the cached token. A
/// refresh takes a separate single-flight mutex and re-checks the cache under
/// it, so an expiry observed by N concurrent callers produces exactly one token
/// exchange rather than N — N simultaneous exchanges being itself a source of
/// the rate limiting this crate works to avoid.
#[derive(Debug)]
pub struct GoogleTokenSource {
    http: reqwest::Client,
    credentials: GoogleCredentials,
    scopes: Vec<String>,
    token_uri: String,
    skew: Duration,
    cached: RwLock<Option<CachedToken>>,
    exchange_lock: Mutex<()>,
}

impl GoogleTokenSource {
    /// Build a source over the given credentials and scopes, using Google's
    /// public token endpoint.
    pub fn new(credentials: GoogleCredentials, scopes: &[&str]) -> Self {
        Self {
            http: reqwest::Client::new(),
            credentials,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            token_uri: DEFAULT_TOKEN_URI.to_string(),
            skew: Duration::seconds(DEFAULT_EXPIRY_SKEW_SECONDS),
            cached: RwLock::new(None),
            exchange_lock: Mutex::new(()),
        }
    }

    /// Build a source from a service-account JSON key file on disk.
    ///
    /// The key file's `token_uri` overrides the default endpoint when present.
    pub fn from_service_account_file(
        key_path: &str,
        admin_email: &str,
        scopes: &[&str],
    ) -> Result<Self> {
        let key_data = std::fs::read_to_string(key_path).map_err(|e| {
            ChalkError::GoogleSync(format!("failed to read service account key: {e}"))
        })?;
        let key: ServiceAccountKey = serde_json::from_str(&key_data).map_err(|e| {
            ChalkError::GoogleSync(format!("failed to parse service account key: {e}"))
        })?;

        let mut source = Self::new(
            GoogleCredentials::ServiceAccount {
                client_email: key.client_email,
                private_key_pem: key.private_key,
                admin_email: admin_email.to_string(),
            },
            scopes,
        );
        if let Some(uri) = key.token_uri {
            source.token_uri = uri;
        }
        Ok(source)
    }

    /// Override the token endpoint. Used by tests to point the exchange at a
    /// mock server, and by service-account keys that name a non-default URI.
    pub fn with_token_uri(mut self, uri: &str) -> Self {
        self.token_uri = uri.to_string();
        self
    }

    /// Override the refresh skew — how long before nominal expiry a token is
    /// treated as stale. Defaults to 60 seconds.
    pub fn with_expiry_skew(mut self, skew: Duration) -> Self {
        self.skew = skew;
        self
    }

    /// Share this source across clients.
    pub fn into_shared(self) -> Arc<dyn TokenProvider> {
        Arc::new(self)
    }

    /// The token endpoint this source exchanges against.
    pub fn token_uri(&self) -> &str {
        &self.token_uri
    }

    /// Fetch a valid token along with its expiry, refreshing if needed.
    ///
    /// Exposed so callers that must record expiry (notably [`crate::auth::GoogleAuth`])
    /// do not have to duplicate the exchange.
    pub async fn token_with_expiry(&self) -> Result<(String, DateTime<Utc>)> {
        if let Some(hit) = self.cached_if_fresh().await {
            return Ok((hit.access_token, hit.expires_at));
        }

        // Single-flight: only one caller performs the exchange. The rest wait
        // here and find the refreshed token on the re-check below.
        let _guard = self.exchange_lock.lock().await;
        if let Some(hit) = self.cached_if_fresh().await {
            return Ok((hit.access_token, hit.expires_at));
        }

        let fresh = self.exchange().await?;
        *self.cached.write().await = Some(fresh.clone());
        Ok((fresh.access_token, fresh.expires_at))
    }

    async fn cached_if_fresh(&self) -> Option<CachedToken> {
        let now = Utc::now();
        self.cached
            .read()
            .await
            .as_ref()
            .filter(|t| t.is_fresh(self.skew, now))
            .cloned()
    }

    async fn exchange(&self) -> Result<CachedToken> {
        let now = Utc::now();
        let form = match &self.credentials {
            GoogleCredentials::ServiceAccount {
                client_email,
                private_key_pem,
                admin_email,
            } => {
                let claims = JwtClaims {
                    iss: client_email.clone(),
                    sub: admin_email.clone(),
                    scope: self.scopes.join(" "),
                    aud: self.token_uri.clone(),
                    iat: now.timestamp(),
                    exp: (now + Duration::seconds(ASSERTION_LIFETIME_SECONDS)).timestamp(),
                };
                let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
                    .map_err(|e| ChalkError::GoogleSync(format!("invalid RSA private key: {e}")))?;
                let jwt = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
                    .map_err(|e| ChalkError::GoogleSync(format!("JWT encoding failed: {e}")))?;
                vec![
                    (
                        "grant_type".to_string(),
                        "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
                    ),
                    ("assertion".to_string(), jwt),
                ]
            }
            GoogleCredentials::OauthRefreshToken {
                client_id,
                client_secret,
                refresh_token,
            } => vec![
                ("grant_type".to_string(), "refresh_token".to_string()),
                ("client_id".to_string(), client_id.clone()),
                ("client_secret".to_string(), client_secret.clone()),
                ("refresh_token".to_string(), refresh_token.clone()),
            ],
        };

        let resp = self
            .http
            .post(&self.token_uri)
            .form(&form)
            .send()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("token exchange request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ChalkError::GoogleSync(format!(
                "token exchange failed ({status}): {body}"
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("token response parse failed: {e}")))?;

        Ok(CachedToken {
            access_token: token_resp.access_token,
            expires_at: now + Duration::seconds(token_resp.expires_in),
        })
    }
}

#[async_trait]
impl TokenProvider for GoogleTokenSource {
    async fn token(&self) -> Result<String> {
        self.token_with_expiry().await.map(|(t, _)| t)
    }

    async fn invalidate(&self) {
        *self.cached.write().await = None;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn device_sync_requests_only_read_only_scopes() {
        // Device sync runs against real district Workspaces with real enrolled
        // Chromebooks. A write scope reaching this array is a production
        // hazard, not a refactor.
        assert_eq!(DEVICE_SYNC_READ_SCOPES.len(), 3);
        for scope in DEVICE_SYNC_READ_SCOPES {
            assert!(scope.ends_with(".readonly"), "non-readonly scope: {scope}");
        }
        assert!(!DEVICE_SYNC_READ_SCOPES.contains(&SCOPE_DEVICE_CHROMEOS));
    }

    /// A 2048-bit RSA private key generated for tests only. Never used
    /// anywhere outside this test module.
    pub(crate) const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
         MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6TfNh8SrGpclp\n\
         6HMvjy0DEf9z5PtK1zIy8nsksOORDWhDRDaarfeTBrQiinkTVJstNFLV7sJ1Q/Z3\n\
         tbMEjW2OO3L+NKdU7KSnpWEmswZlZ8EpcLHFcmnidNa47KJ2Zd/WZBGf+6oVtldw\n\
         mSu+bI6UXqdSvvwRiqj+KKQW7SdRLb2uWEPwsMGTT+DLRtyxoBkwoBqwTf63fTZl\n\
         /9X8xYxGn+j8EJh8qrqgHezDpw89CS2ddMt9KdubTmf6p2+7RJm1lG2kPTZVbxfl\n\
         x+ak0d0vvT2wlkwEHphJiAZ7S/Wzooa0KvjxkGTI+FFPB+D3Iseh7ivnWEq/sxHy\n\
         FZcQZCcnAgMBAAECggEAGndEYd9+siWPDUqGQnVWcZ826OHYiPM1IGOt9rJiQZLk\n\
         AtpH34VjLDHBmT6OoJ5eRPev5NA8M6hp9OuM+NKWg6QSW+Zi9v9/DInD2VmJSRKK\n\
         MDbgKipsvEzYzABhu+wQ9kXU8yMvMFJs7YP04OJPBujDYE/dQyithR2E4fTipvdY\n\
         HfKBwOWSqe/St6nQ06bxrn5zu6XMK+dTvw9hu/jkSX3SxwJtR8ImTX5jUMpd0raA\n\
         g6dirHw7XfjkC17elXufTdehfgqkCkMQctuMQjWXMj5OC78O8eXIKhOZfCx0APUc\n\
         SVse+y28FCL6wtr9z0WdumRIqUqGSdaWYAxBhg+esQKBgQDyZPLzHNroCTgYf+0H\n\
         68oAdXKjTy2QgqFIThiUry99aeUogtWgovBS+K+gqWb36MclCn7aExQUIcYkl7DB\n\
         3Ff5xxn9aLfUdIur/iuC6eXZ5937G1kK4pdzoeNWCeo8OPCaoW8hb0nvfMPDS9g7\n\
         WwhRlnFx8UYohnoNUafS7CC+ZQKBgQDEwwbX2w7kKrgEzXQa59RM05dvSt3kV9l3\n\
         BPREWHU4GQAlzkYfxYF72MwKdie2Lc7JN0mUsm7f4wFAPqRafT+I9WHDnQXY+NXt\n\
         o6M7s2RNawcDZInl3lwGk6G7SHepmh8NYxjiK2tFIDxIx1vYJIF+WU3lo33FDXpY\n\
         h/BV0E9gmwKBgQC6cDsOE1usraqf7YV7Wjj9MVkDk5sQU+mJm8f8VOLKK/E+v6Ng\n\
         8vK2XuF3SdURSdIjA3eedJ40/eVRr/scoUZpsGKlLy52E0568/yzrQRGHrn2sopC\n\
         fRbQsewR+X5Y49LsnM7FgLv1oJlSVbvzq4kyd+y6H0I/WW/3Xp8e9NAaoQKBgQCg\n\
         h7FkmO+cThIWsP0CGpSGHbeWcFF6xAXDagJUZIs2Ood5UMK7lysePPGzs1SQ+OyW\n\
         FApvS+jTtuRFYxY6UadteS3LJ6gmrlXzbSd3RNQXqbNuHC+5oGIaZ4ZzQxuF/x1I\n\
         kcoydFQvcK5efnA7dwVDbV71dR7ejzF7W2VEzhCE8wKBgFJ9Ro3tNIuqvc2mWZpr\n\
         0U766jN8S6RaHtMeiEiy81IL/vxWWrAAuphCAQM179VTYgOSBfaxxndmE34RlTMB\n\
         tokgaBA8flLko3cDhXlavGtHCD/VojxWUWeX4Ou9/xSy/kIbd9r868SdcBo3BZe1\n\
         6xUvIBqnkJUHjuG/cXMQaxpP\n\
         -----END PRIVATE KEY-----";

    /// A [`TokenProvider`] that counts how many times it was asked for a token
    /// and how many times it was invalidated.
    #[derive(Debug, Default)]
    pub(crate) struct CountingTokenProvider {
        pub(crate) tokens_issued: AtomicUsize,
        pub(crate) invalidations: AtomicUsize,
    }

    #[async_trait]
    impl TokenProvider for CountingTokenProvider {
        async fn token(&self) -> Result<String> {
            let n = self.tokens_issued.fetch_add(1, Ordering::SeqCst);
            Ok(format!("token-{n}"))
        }

        async fn invalidate(&self) {
            self.invalidations.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn sa_credentials() -> GoogleCredentials {
        GoogleCredentials::ServiceAccount {
            client_email: "svc@test-project.iam.gserviceaccount.com".to_string(),
            private_key_pem: TEST_RSA_PRIVATE_KEY.to_string(),
            admin_email: "admin@example.com".to_string(),
        }
    }

    async fn mount_token_endpoint(server: &MockServer, token: &str, expires_in: i64) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": token,
                "expires_in": expires_in,
                "token_type": "Bearer",
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn static_provider_returns_token_and_survives_invalidate() {
        let p = StaticTokenProvider::new("fixed");
        assert_eq!(p.token().await.unwrap(), "fixed");
        p.invalidate().await;
        assert_eq!(p.token().await.unwrap(), "fixed");
    }

    #[tokio::test]
    async fn service_account_exchange_returns_token() {
        let server = MockServer::start().await;
        mount_token_endpoint(&server, "ya29.sa-token", 3600).await;

        let source = GoogleTokenSource::new(sa_credentials(), &[SCOPE_DEVICE_CHROMEOS])
            .with_token_uri(&format!("{}/token", server.uri()));

        assert_eq!(source.token().await.unwrap(), "ya29.sa-token");
    }

    #[tokio::test]
    async fn oauth_refresh_exchange_returns_token() {
        let server = MockServer::start().await;
        mount_token_endpoint(&server, "ya29.oauth-token", 3600).await;

        // The OAuth flow has no key file to carry `token_uri`; `with_token_uri`
        // is the only reason this path is testable at all.
        let source = GoogleTokenSource::new(
            GoogleCredentials::OauthRefreshToken {
                client_id: "cid".to_string(),
                client_secret: "secret".to_string(),
                refresh_token: "rt".to_string(),
            },
            &[SCOPE_DEVICE_CHROMEOS],
        )
        .with_token_uri(&format!("{}/token", server.uri()));

        assert_eq!(source.token().await.unwrap(), "ya29.oauth-token");
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let body = String::from_utf8(reqs[0].body.clone()).unwrap();
        assert!(body.contains("grant_type=refresh_token"), "body was {body}");
        assert!(body.contains("refresh_token=rt"), "body was {body}");
    }

    #[tokio::test]
    async fn fresh_token_is_cached_across_calls() {
        let server = MockServer::start().await;
        mount_token_endpoint(&server, "cached", 3600).await;

        let source = GoogleTokenSource::new(sa_credentials(), &[])
            .with_token_uri(&format!("{}/token", server.uri()));

        for _ in 0..5 {
            assert_eq!(source.token().await.unwrap(), "cached");
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn expired_token_triggers_exactly_one_new_exchange() {
        let server = MockServer::start().await;
        // A 30-second lifetime is inside the default 60-second skew window, so
        // every call sees the cached token as stale.
        mount_token_endpoint(&server, "short-lived", 30).await;

        let source = GoogleTokenSource::new(sa_credentials(), &[])
            .with_token_uri(&format!("{}/token", server.uri()));

        source.token().await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        source.token().await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// Number of concurrent callers used by the single-flight tests.
    const SINGLE_FLIGHT_CALLERS: usize = 16;

    /// How long the mocked token endpoint takes to answer. Long enough that
    /// every caller is provably still waiting when the first exchange lands.
    const EXCHANGE_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

    #[tokio::test]
    async fn concurrent_callers_trigger_exactly_one_exchange() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(EXCHANGE_DELAY)
                    .set_body_json(serde_json::json!({
                        "access_token": "single-flight",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                    })),
            )
            .mount(&server)
            .await;

        let source = Arc::new(
            GoogleTokenSource::new(sa_credentials(), &[])
                .with_token_uri(&format!("{}/token", server.uri())),
        );

        // The barrier removes the scheduling assumption: no caller proceeds
        // into `token()` until all of them have arrived, so they are provably
        // contending rather than incidentally overlapping.
        let barrier = Arc::new(tokio::sync::Barrier::new(SINGLE_FLIGHT_CALLERS));
        let started = std::time::Instant::now();

        let mut handles = Vec::new();
        for _ in 0..SINGLE_FLIGHT_CALLERS {
            let s = Arc::clone(&source);
            let b = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                b.wait().await;
                s.token().await
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap().unwrap(), "single-flight");
        }
        let elapsed = started.elapsed();

        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "single-flight must collapse concurrent refreshes into one exchange"
        );

        // Proves the callers really did contend. Serialised callers would each
        // pay the delay (16 × 200ms = 3.2s); one shared exchange costs one.
        // The bound is deliberately loose — it is a concurrency proof, not a
        // performance assertion.
        assert!(
            elapsed < EXCHANGE_DELAY * 4,
            "callers did not overlap: {elapsed:?} suggests serialised exchanges"
        );
    }

    /// Negative control for the test above.
    ///
    /// Without it, `== 1` could pass for the wrong reason — callers that never
    /// actually overlap also produce one request. Here each caller gets its
    /// *own* source, so there is no shared cache to collapse into: under the
    /// identical barrier and delay the mock must see all 16. That the count
    /// tracks the number of caches, and not the harness, is what makes the
    /// `== 1` above meaningful.
    #[tokio::test]
    async fn without_a_shared_cache_every_caller_exchanges() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(EXCHANGE_DELAY)
                    .set_body_json(serde_json::json!({
                        "access_token": "per-caller",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                    })),
            )
            .mount(&server)
            .await;

        let token_uri = format!("{}/token", server.uri());
        let barrier = Arc::new(tokio::sync::Barrier::new(SINGLE_FLIGHT_CALLERS));

        let mut handles = Vec::new();
        for _ in 0..SINGLE_FLIGHT_CALLERS {
            let uri = token_uri.clone();
            let b = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                let source = GoogleTokenSource::new(sa_credentials(), &[]).with_token_uri(&uri);
                b.wait().await;
                source.token().await
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap().unwrap(), "per-caller");
        }

        assert_eq!(
            server.received_requests().await.unwrap().len(),
            SINGLE_FLIGHT_CALLERS,
            "the harness must be able to observe N exchanges, or `== 1` proves nothing"
        );
    }

    #[tokio::test]
    async fn invalidate_forces_a_new_exchange() {
        let server = MockServer::start().await;
        mount_token_endpoint(&server, "tok", 3600).await;

        let source = GoogleTokenSource::new(sa_credentials(), &[])
            .with_token_uri(&format!("{}/token", server.uri()));

        source.token().await.unwrap();
        source.token().await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);

        source.invalidate().await;
        source.token().await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn exchange_failure_surfaces_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "invalid_grant"})),
            )
            .mount(&server)
            .await;

        let source = GoogleTokenSource::new(sa_credentials(), &[])
            .with_token_uri(&format!("{}/token", server.uri()));

        let err = source.token().await.unwrap_err().to_string();
        assert!(err.contains("token exchange failed"), "{err}");
        assert!(err.contains("invalid_grant"), "{err}");
    }

    /// Write `contents` to a key file inside a fresh temp directory.
    ///
    /// The directory is unique per call and cleaned up on drop. A fixed path
    /// under `temp_dir()` is not safe here: two test binaries running at once
    /// (`cargo test --all`, or a concurrent run) share it, and one deleting
    /// the fixture mid-read fails the other.
    pub(crate) fn write_key_file(contents: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("sa.json");
        std::fs::write(&path, contents).expect("write key file");
        let path = path.to_str().expect("utf-8 path").to_string();
        (dir, path)
    }

    #[test]
    fn from_service_account_file_reads_token_uri_from_key() {
        let (_dir, path) = write_key_file(
            &serde_json::json!({
                "client_email": "svc@p.iam.gserviceaccount.com",
                "private_key": TEST_RSA_PRIVATE_KEY,
                "token_uri": "https://example.test/token",
            })
            .to_string(),
        );

        let source = GoogleTokenSource::from_service_account_file(&path, "a@b.c", &[]).unwrap();
        assert_eq!(source.token_uri(), "https://example.test/token");
    }

    #[test]
    fn from_service_account_file_defaults_token_uri_when_absent() {
        let (_dir, path) = write_key_file(
            &serde_json::json!({
                "client_email": "svc@p.iam.gserviceaccount.com",
                "private_key": TEST_RSA_PRIVATE_KEY,
            })
            .to_string(),
        );

        let source = GoogleTokenSource::from_service_account_file(&path, "a@b.c", &[]).unwrap();
        assert_eq!(source.token_uri(), DEFAULT_TOKEN_URI);
    }

    #[test]
    fn from_service_account_file_missing_and_malformed() {
        let missing =
            GoogleTokenSource::from_service_account_file("/nonexistent/sa.json", "a@b.c", &[]);
        assert!(missing
            .unwrap_err()
            .to_string()
            .contains("failed to read service account key"));

        let (_dir, path) = write_key_file("not json");
        let bad = GoogleTokenSource::from_service_account_file(&path, "a@b.c", &[]);
        assert!(bad
            .unwrap_err()
            .to_string()
            .contains("failed to parse service account key"));
    }

    #[test]
    fn credentials_debug_redacts_secrets() {
        let sa = format!("{:?}", sa_credentials());
        assert!(sa.contains("<redacted>"));
        assert!(!sa.contains("BEGIN PRIVATE KEY"));

        let oauth = format!(
            "{:?}",
            GoogleCredentials::OauthRefreshToken {
                client_id: "cid".to_string(),
                client_secret: "hunter2".to_string(),
                refresh_token: "1//secret".to_string(),
            }
        );
        assert!(!oauth.contains("hunter2"));
        assert!(!oauth.contains("1//secret"));
    }

    #[test]
    fn cached_token_freshness_respects_skew() {
        let now = Utc::now();
        let t = CachedToken {
            access_token: "x".to_string(),
            expires_at: now + Duration::seconds(90),
        };
        assert!(t.is_fresh(Duration::seconds(60), now));
        assert!(!t.is_fresh(Duration::seconds(120), now));
    }
}
