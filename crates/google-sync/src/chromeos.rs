//! ChromeOS device reads against the Google Admin Directory API.
//!
//! **This module is read-only by construction.** There is no `patch_device`,
//! no `batchChangeStatus`, no `moveDevicesToOu` and no `issueCommand` — not
//! behind a flag, not unrouted. Write-back is a separate pass with its own
//! authorization review, and until it lands the only scopes this client needs
//! are the `.readonly` variants in [`crate::token`].
//!
//! Two design decisions are load-bearing and both are deliberate departures
//! from the incumbent add-on studied in `plans/CHROMEBOOK_GETTER_STUDY.md`:
//!
//! 1. **One listing at the root OU, never a per-OU fan-out.** Listing at
//!    `orgUnitPath=/` is recursive, so it is a strict superset of any fan-out,
//!    and callers filter locally on the `orgUnitPath` each device already
//!    carries. The decisive reason is schema, not taste:
//!    `google_device_sync_cursors` is keyed by resource with a *single*
//!    `page_token`, so a resumable cursor and N concurrent per-OU cursors are
//!    mutually incompatible. `orgUnitPath` is therefore not a parameter of
//!    [`ChromeOsClient::list_devices`] at all — fan-out is unrepresentable.
//! 2. **`maxResults` defaults to 200, not the documented maximum of 300.**
//!    200 has years of field evidence at district scale; a `projection=FULL`
//!    page is large, and the page size is the likeliest thing to throttle or
//!    time out. 300 is available via [`ChromeOsClient::with_max_results`] for
//!    anyone who measures it to be better, but nothing picks it silently.
//!
//! Every request runs through [`RetryExecutor`], which resolves a fresh bearer
//! token per attempt (a 20k-device walk outlives an access token), paces calls
//! through one shared token bucket, and classifies failures on Google's JSON
//! `reason` field rather than the HTTP status.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chalk_core::error::{ChalkError, Result};
use chrono::{DateTime, NaiveDate, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::backoff::{OperationKind, RateLimiter, RetryExecutor, RetryPolicy};
use crate::models::{GoogleOrgUnit, GoogleOrgUnitList, GoogleUserList};
use crate::token::TokenProvider;

const GOOGLE_ADMIN_API_BASE: &str = "https://admin.googleapis.com";

/// Page size used unless overridden. See the module docs for why this is not
/// [`MAX_RESULTS_LIMIT`].
pub const DEFAULT_MAX_RESULTS: u32 = 200;

/// The largest `maxResults` `chromeosdevices.list` documents.
pub const MAX_RESULTS_LIMIT: u32 = 300;

/// The only `orgUnitPath` this client ever sends. Recursive, so one walk sees
/// the whole estate.
pub const ROOT_ORG_UNIT_PATH: &str = "/";

/// `projection=FULL` is mandatory, not an optimization: `autoUpdateExpiration`,
/// `supportEndDate`, `lastSync`, `recentUsers` and `activeTimeRanges` are all
/// absent from the `BASIC` projection.
pub const PROJECTION_FULL: &str = "FULL";

/// Google's limit on `annotatedUser`, in characters.
pub const MAX_ANNOTATED_USER_LEN: usize = 100;
/// Google's limit on `annotatedLocation`, in characters.
pub const MAX_ANNOTATED_LOCATION_LEN: usize = 200;
/// Google's limit on `notes`, in characters.
pub const MAX_NOTES_LEN: usize = 500;

/// Read-only Admin Directory client for ChromeOS devices, OUs and users.
#[derive(Debug, Clone)]
pub struct ChromeOsClient {
    http: reqwest::Client,
    base_url: String,
    customer_id: String,
    retry: RetryExecutor,
    max_results: u32,
    api_calls: Arc<AtomicU64>,
}

impl ChromeOsClient {
    /// Build a client that resolves its bearer token through `auth` on every
    /// request.
    ///
    /// `customer_id` is the Directory API customer — `"my_customer"` resolves
    /// to the impersonated admin's own domain and is the usual value.
    pub fn new(auth: Arc<dyn TokenProvider>, customer_id: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: GOOGLE_ADMIN_API_BASE.to_string(),
            customer_id: customer_id.to_string(),
            retry: RetryExecutor::new(auth),
            max_results: DEFAULT_MAX_RESULTS,
            api_calls: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Point the client at another origin (wiremock in tests).
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Replace the retry policy — tests use [`RetryPolicy::test_fast`] to walk
    /// the retry paths without sleeping.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry = self.retry.with_policy(policy);
        self
    }

    /// Replace the shared client-side rate limiter.
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.retry = self.retry.with_rate_limiter(limiter);
        self
    }

    /// Override the page size, clamped to `1..=`[`MAX_RESULTS_LIMIT`].
    pub fn with_max_results(mut self, n: u32) -> Self {
        self.max_results = n.clamp(1, MAX_RESULTS_LIMIT);
        self
    }

    /// The page size in force.
    pub fn max_results(&self) -> u32 {
        self.max_results
    }

    /// The Directory API customer this client addresses.
    pub fn customer_id(&self) -> &str {
        &self.customer_id
    }

    /// Requests issued so far, for `google_device_sync_runs.api_calls`.
    /// Counts logical calls; retries within one call are counted once and
    /// show up separately as [`ChromeOsClient::throttle_events`].
    pub fn api_calls(&self) -> u64 {
        self.api_calls.load(Ordering::Relaxed)
    }

    /// Throttle responses observed so far, for
    /// `google_device_sync_runs.throttle_events`.
    pub fn throttle_events(&self) -> u64 {
        self.retry.throttle_events()
    }

    fn devices_url(&self) -> String {
        format!(
            "{}/admin/directory/v1/customer/{}/devices/chromeos",
            self.base_url, self.customer_id
        )
    }

    fn orgunits_url(&self) -> String {
        format!(
            "{}/admin/directory/v1/customer/{}/orgunits",
            self.base_url, self.customer_id
        )
    }

    fn users_url(&self) -> String {
        format!("{}/admin/directory/v1/users", self.base_url)
    }

    async fn parse_json<T: DeserializeOwned>(
        resp: reqwest::Response,
        operation: &str,
    ) -> Result<T> {
        resp.json::<T>()
            .await
            .map_err(|e| ChalkError::GoogleSync(format!("{operation} parse failed: {e}")))
    }

    /// One page of ChromeOS devices from the whole estate.
    ///
    /// Always `projection=FULL` at `orgUnitPath=/`. `query` is Google's device
    /// search syntax (`asset_id:…`, `sync:…`, `status:…`); `None` lists
    /// everything. The returned [`ChromeOsDevicePage::next_page_token`] is the
    /// value to persist into the cursor and pass back in — a crashed run
    /// resumes mid-pagination instead of restarting the fleet walk.
    pub async fn list_devices(
        &self,
        page_token: Option<&str>,
        query: Option<&str>,
    ) -> Result<ChromeOsDevicePage> {
        let url = self.devices_url();
        let max_results = self.max_results.to_string();
        self.api_calls.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .retry
            .execute(OperationKind::Read, "list ChromeOS devices", || {
                let mut req = self.http.get(&url).query(&[
                    ("maxResults", max_results.as_str()),
                    ("projection", PROJECTION_FULL),
                    ("orgUnitPath", ROOT_ORG_UNIT_PATH),
                ]);
                if let Some(token) = page_token {
                    req = req.query(&[("pageToken", token)]);
                }
                if let Some(q) = query {
                    req = req.query(&[("query", q)]);
                }
                req
            })
            .await?;
        let page: ChromeOsDeviceList = Self::parse_json(resp, "list ChromeOS devices").await?;
        Ok(ChromeOsDevicePage {
            devices: page.chromeosdevices.unwrap_or_default(),
            next_page_token: page.next_page_token,
        })
    }

    /// The whole OU tree in one `orgunits.list?type=all` call.
    ///
    /// One call, never one per subtree: the incumbent's unbounded per-OU
    /// fan-out is the likeliest source of its 403 storms.
    pub async fn list_org_units(&self) -> Result<Vec<GoogleOrgUnit>> {
        let url = self.orgunits_url();
        self.api_calls.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .retry
            .execute(OperationKind::Read, "list OUs", || {
                self.http.get(&url).query(&[("type", "all")])
            })
            .await?;
        let list: GoogleOrgUnitList = Self::parse_json(resp, "list OUs").await?;
        Ok(list.organization_units.unwrap_or_default())
    }

    /// One page of directory users.
    ///
    /// Present for enrichment and diagnostics; roster matching joins against
    /// Chalk's own `users` table, not this listing.
    pub async fn list_directory_users(&self, page_token: Option<&str>) -> Result<GoogleUserList> {
        let url = self.users_url();
        let max_results = self.max_results.to_string();
        self.api_calls.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .retry
            .execute(OperationKind::Read, "list directory users", || {
                let mut req = self.http.get(&url).query(&[
                    ("customer", self.customer_id.as_str()),
                    ("maxResults", max_results.as_str()),
                ]);
                if let Some(token) = page_token {
                    req = req.query(&[("pageToken", token)]);
                }
                req
            })
            .await?;
        Self::parse_json(resp, "list directory users").await
    }
}

/// One page of devices plus the token that continues the walk.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChromeOsDevicePage {
    pub devices: Vec<ChromeOsDevice>,
    /// `None` on the last page.
    pub next_page_token: Option<String>,
}

/// The wire shape of `chromeosdevices.list`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChromeOsDeviceList {
    chromeosdevices: Option<Vec<ChromeOsDevice>>,
    next_page_token: Option<String>,
}

/// A ChromeOS device as returned under `projection=FULL`.
///
/// Unknown fields are ignored rather than rejected: Google adds fields to this
/// resource regularly and a sync that fails on an unrecognized key would be a
/// self-inflicted outage.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ChromeOsDevice {
    /// Directory API `deviceId` — the join key against `assets`.
    pub device_id: String,
    pub serial_number: Option<String>,
    pub model: Option<String>,
    pub org_unit_path: Option<String>,
    /// Preferred over `org_unit_path` for identity: paths break on `&` and `+`.
    pub org_unit_id: Option<String>,
    pub annotated_user: Option<String>,
    pub annotated_asset_id: Option<String>,
    pub annotated_location: Option<String>,
    pub notes: Option<String>,
    /// `ACTIVE` | `DEPROVISIONED` | `DISABLED` | `INACTIVE` | …
    pub status: Option<String>,
    pub os_version: Option<String>,
    pub platform_version: Option<String>,
    pub firmware_version: Option<String>,
    pub mac_address: Option<String>,
    pub last_sync: Option<DateTime<Utc>>,
    /// Milliseconds since the epoch, as a string. Google's own encoding.
    pub auto_update_expiration: Option<String>,
    /// RFC 3339. The older AUE field; still populated on many devices.
    pub support_end_date: Option<DateTime<Utc>>,
    pub recent_users: Vec<RecentUser>,
    pub last_known_network: Vec<LastKnownNetwork>,
}

/// One entry of `recentUsers`. Google returns these newest-first.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RecentUser {
    pub email: Option<String>,
    /// `USER_TYPE_MANAGED` for domain accounts, `USER_TYPE_UNMANAGED`
    /// otherwise. Unmanaged sign-ins are personal Google accounts and must
    /// never become a roster match.
    #[serde(rename = "type")]
    pub user_type: Option<String>,
}

/// `type` value marking a recent user as a managed domain account.
pub const USER_TYPE_MANAGED: &str = "USER_TYPE_MANAGED";

impl RecentUser {
    /// True when this sign-in is a managed domain account with an email.
    pub fn is_managed(&self) -> bool {
        self.email.is_some() && self.user_type.as_deref() == Some(USER_TYPE_MANAGED)
    }
}

/// One entry of `lastKnownNetwork`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LastKnownNetwork {
    pub ip_address: Option<String>,
    pub wan_ip_address: Option<String>,
}

impl ChromeOsDevice {
    /// The auto-update expiration as a date.
    ///
    /// Prefers `autoUpdateExpiration` (epoch milliseconds in a string, which
    /// is genuinely how Google encodes it) and falls back to the older
    /// `supportEndDate`.
    pub fn aue_date(&self) -> Option<NaiveDate> {
        if let Some(raw) = self.auto_update_expiration.as_deref() {
            if let Ok(millis) = raw.trim().parse::<i64>() {
                if let Some(dt) = DateTime::from_timestamp_millis(millis) {
                    return Some(dt.date_naive());
                }
            }
        }
        self.support_end_date.map(|d| d.date_naive())
    }

    /// The device's most recent LAN/WAN address, if Google reported one.
    pub fn last_known_ip(&self) -> Option<&str> {
        self.last_known_network.iter().find_map(|n| {
            n.ip_address
                .as_deref()
                .or(n.wan_ip_address.as_deref())
                .filter(|s| !s.is_empty())
        })
    }

    /// True when Google reports the device as deprovisioned — the one status
    /// Google is authoritative for.
    pub fn is_deprovisioned(&self) -> bool {
        self.status
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("DEPROVISIONED"))
    }
}

/// A validated `annotatedUser` / `annotatedLocation` / `notes` triple.
///
/// Nothing in this crate writes these fields today — there is no write path.
/// The type exists so that when write-back lands, oversize input is rejected
/// locally with a field name and a limit, rather than producing the opaque
/// Google error the incumbent's users hit. Constructing the value is the only
/// way to express a metadata write, so the validation cannot be bypassed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnnotatedFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    annotated_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotated_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

/// Reject `value` if it is longer than `max` *characters*. Google counts
/// characters, so a byte length would reject valid accented input.
fn check_len(field: &str, value: &str, max: usize) -> Result<()> {
    let len = value.chars().count();
    if len > max {
        return Err(ChalkError::GoogleSync(format!(
            "{field} is {len} characters; Google's limit is {max}"
        )));
    }
    Ok(())
}

impl AnnotatedFields {
    /// An empty set of fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `annotatedUser`, rejecting input over [`MAX_ANNOTATED_USER_LEN`].
    pub fn with_annotated_user(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        check_len("annotatedUser", &value, MAX_ANNOTATED_USER_LEN)?;
        self.annotated_user = Some(value);
        Ok(self)
    }

    /// Set `annotatedLocation`, rejecting input over
    /// [`MAX_ANNOTATED_LOCATION_LEN`].
    pub fn with_annotated_location(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        check_len("annotatedLocation", &value, MAX_ANNOTATED_LOCATION_LEN)?;
        self.annotated_location = Some(value);
        Ok(self)
    }

    /// Set `notes`, rejecting input over [`MAX_NOTES_LEN`].
    pub fn with_notes(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        check_len("notes", &value, MAX_NOTES_LEN)?;
        self.notes = Some(value);
        Ok(self)
    }

    pub fn annotated_user(&self) -> Option<&str> {
        self.annotated_user.as_deref()
    }

    pub fn annotated_location(&self) -> Option<&str> {
        self.annotated_location.as_deref()
    }

    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }

    /// True when no field is set, i.e. the update would be a no-op.
    pub fn is_empty(&self) -> bool {
        self.annotated_user.is_none() && self.annotated_location.is_none() && self.notes.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::StaticTokenProvider;
    use wiremock::matchers::{bearer_token, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A client pointed at a mock server, with production retry *counts* but
    /// zero delay so retry paths never sleep.
    async fn setup() -> (MockServer, ChromeOsClient) {
        let server = MockServer::start().await;
        let client = ChromeOsClient::new(
            Arc::new(StaticTokenProvider::new("test-token")),
            "my_customer",
        )
        .with_base_url(&server.uri())
        .with_retry_policy(RetryPolicy::test_fast())
        .with_rate_limiter(RateLimiter::unlimited());
        (server, client)
    }

    const DEVICES_PATH: &str = "/admin/directory/v1/customer/my_customer/devices/chromeos";

    fn device_json(device_id: &str) -> serde_json::Value {
        serde_json::json!({
            "deviceId": device_id,
            "serialNumber": "SN-1",
            "model": "Acer Chromebook 311",
            "orgUnitPath": "/Students/HS",
            "orgUnitId": "id:ou123",
            "status": "ACTIVE",
        })
    }

    #[tokio::test]
    async fn list_devices_sends_full_projection_and_default_page_size() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path(DEVICES_PATH))
            .and(bearer_token("test-token"))
            .and(query_param("projection", "FULL"))
            .and(query_param("maxResults", "200"))
            .and(query_param("orgUnitPath", "/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chromeosdevices": [device_json("dev-1")]
            })))
            .mount(&server)
            .await;

        let page = client.list_devices(None, None).await.unwrap();
        assert_eq!(page.devices.len(), 1);
        assert_eq!(page.devices[0].device_id, "dev-1");
        assert!(page.next_page_token.is_none());
        assert_eq!(client.api_calls(), 1);
    }

    #[tokio::test]
    async fn max_results_is_configurable_and_clamped_to_the_documented_limit() {
        let (server, client) = setup().await;
        let client = client.with_max_results(9_000);
        assert_eq!(client.max_results(), MAX_RESULTS_LIMIT);

        Mock::given(method("GET"))
            .and(path(DEVICES_PATH))
            .and(query_param("maxResults", "300"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let page = client.list_devices(None, None).await.unwrap();
        assert!(page.devices.is_empty());
    }

    #[tokio::test]
    async fn list_devices_passes_page_token_and_query_through() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path(DEVICES_PATH))
            .and(query_param("pageToken", "tok-2"))
            .and(query_param("query", "asset_id:00123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chromeosdevices": [device_json("dev-2")],
                "nextPageToken": "tok-3"
            })))
            .mount(&server)
            .await;

        let page = client
            .list_devices(Some("tok-2"), Some("asset_id:00123"))
            .await
            .unwrap();
        assert_eq!(page.next_page_token.as_deref(), Some("tok-3"));
    }

    #[tokio::test]
    async fn list_devices_never_sends_a_non_root_org_unit_path() {
        // The signature has no orgUnitPath parameter; this asserts the wire
        // form matches, so a future refactor cannot reintroduce fan-out
        // without failing here.
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path(DEVICES_PATH))
            .and(query_param("orgUnitPath", "/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        client.list_devices(None, None).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let ous: Vec<String> = requests[0]
            .url
            .query_pairs()
            .filter(|(k, _)| k == "orgUnitPath")
            .map(|(_, v)| v.to_string())
            .collect();
        assert_eq!(ous, vec!["/".to_string()]);
    }

    #[tokio::test]
    async fn list_devices_retries_a_rate_limit_403_then_succeeds() {
        let (server, client) = setup().await;

        // Directory API returns 403 — not 429 — for rate limiting. Classified
        // on `reason`, so this is retryable while a `forbidden` 403 is not.
        Mock::given(method("GET"))
            .and(path(DEVICES_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": {"errors": [{"reason": "rateLimitExceeded", "message": "slow down"}]}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(DEVICES_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "chromeosdevices": [device_json("dev-1")]
            })))
            .mount(&server)
            .await;

        let page = client.list_devices(None, None).await.unwrap();
        assert_eq!(page.devices.len(), 1);
        assert_eq!(
            client.throttle_events(),
            1,
            "the throttle must be counted for google_device_sync_runs"
        );
    }

    #[tokio::test]
    async fn list_devices_does_not_retry_a_permission_403() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path(DEVICES_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": {"errors": [{"reason": "forbidden", "message": "not authorized"}]}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let err = client.list_devices(None, None).await.unwrap_err();
        assert!(err.to_string().contains("not authorized"), "{err}");
    }

    #[tokio::test]
    async fn list_org_units_is_one_call_for_the_whole_tree() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/customer/my_customer/orgunits"))
            .and(query_param("type", "all"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "organizationUnits": [
                    {"name": "Students", "orgUnitPath": "/Students", "orgUnitId": "id:a"},
                    {"name": "Arts & Crafts", "orgUnitPath": "/Arts & Crafts", "orgUnitId": "id:b"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let ous = client.list_org_units().await.unwrap();
        assert_eq!(ous.len(), 2);
        assert_eq!(ous[1].org_unit_id.as_deref(), Some("id:b"));
    }

    #[tokio::test]
    async fn list_directory_users_paginates() {
        let (server, client) = setup().await;

        Mock::given(method("GET"))
            .and(path("/admin/directory/v1/users"))
            .and(query_param("customer", "my_customer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "users": [{
                    "primaryEmail": "a@school.edu",
                    "name": {"givenName": "A", "familyName": "User"}
                }],
                "nextPageToken": "u2"
            })))
            .mount(&server)
            .await;

        let page = client.list_directory_users(None).await.unwrap();
        assert_eq!(page.users.unwrap().len(), 1);
        assert_eq!(page.next_page_token.as_deref(), Some("u2"));
    }

    #[test]
    fn full_projection_device_deserializes_including_recent_users() {
        let json = serde_json::json!({
            "deviceId": "dev-1",
            "serialNumber": "5CD1234ABC",
            "model": "Lenovo 100e",
            "orgUnitPath": "/Students/MS",
            "orgUnitId": "id:ou77",
            "annotatedUser": "jdoe@school.edu",
            "annotatedAssetId": "00123",
            "annotatedLocation": "Room 12",
            "notes": "cracked bezel",
            "status": "ACTIVE",
            "osVersion": "126.0.6478.0",
            "platformVersion": "15886.0.0",
            "firmwareVersion": "Google_Coral",
            "macAddress": "aabbccddeeff",
            "lastSync": "2026-07-20T13:45:00.000Z",
            "autoUpdateExpiration": "1908921600000",
            "recentUsers": [
                {"type": "USER_TYPE_MANAGED", "email": "newest@school.edu"},
                {"type": "USER_TYPE_UNMANAGED", "email": "personal@gmail.com"}
            ],
            "lastKnownNetwork": [{"ipAddress": "10.0.4.9", "wanIpAddress": "203.0.113.7"}],
            "someFieldGoogleAddedLastTuesday": {"nested": true}
        });

        let device: ChromeOsDevice = serde_json::from_value(json).unwrap();
        assert_eq!(device.device_id, "dev-1");
        assert_eq!(device.annotated_asset_id.as_deref(), Some("00123"));
        assert_eq!(device.recent_users.len(), 2);
        assert!(device.recent_users[0].is_managed());
        assert!(!device.recent_users[1].is_managed());
        assert_eq!(device.last_known_ip(), Some("10.0.4.9"));
        assert!(device.last_sync.is_some());
        assert!(!device.is_deprovisioned());
    }

    #[test]
    fn aue_date_reads_epoch_millis_then_falls_back_to_support_end_date() {
        let mut device = ChromeOsDevice {
            // 2030-06-01T00:00:00Z
            auto_update_expiration: Some("1906502400000".to_string()),
            ..ChromeOsDevice::default()
        };
        assert_eq!(
            device.aue_date(),
            Some(NaiveDate::from_ymd_opt(2030, 6, 1).unwrap())
        );

        device.auto_update_expiration = None;
        device.support_end_date = Some(
            DateTime::parse_from_rfc3339("2028-09-30T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert_eq!(
            device.aue_date(),
            Some(NaiveDate::from_ymd_opt(2028, 9, 30).unwrap())
        );

        device.support_end_date = None;
        assert_eq!(device.aue_date(), None);
    }

    #[test]
    fn aue_date_ignores_a_malformed_expiration_rather_than_failing() {
        let device = ChromeOsDevice {
            auto_update_expiration: Some("not-a-number".to_string()),
            ..ChromeOsDevice::default()
        };
        assert_eq!(device.aue_date(), None);
    }

    #[test]
    fn deprovisioned_status_is_recognized_case_insensitively() {
        let device = ChromeOsDevice {
            status: Some("deprovisioned".to_string()),
            ..ChromeOsDevice::default()
        };
        assert!(device.is_deprovisioned());
    }

    #[test]
    fn annotated_fields_accept_input_at_the_limit() {
        let fields = AnnotatedFields::new()
            .with_annotated_user("u".repeat(MAX_ANNOTATED_USER_LEN))
            .unwrap()
            .with_annotated_location("l".repeat(MAX_ANNOTATED_LOCATION_LEN))
            .unwrap()
            .with_notes("n".repeat(MAX_NOTES_LEN))
            .unwrap();
        assert!(!fields.is_empty());
        assert_eq!(fields.annotated_user().unwrap().len(), 100);
    }

    #[test]
    fn annotated_fields_reject_oversize_input_with_the_field_and_limit() {
        let err = AnnotatedFields::new()
            .with_annotated_user("u".repeat(MAX_ANNOTATED_USER_LEN + 1))
            .unwrap_err()
            .to_string();
        assert!(err.contains("annotatedUser"), "{err}");
        assert!(err.contains("101"), "{err}");
        assert!(err.contains("100"), "{err}");

        assert!(AnnotatedFields::new()
            .with_annotated_location("l".repeat(MAX_ANNOTATED_LOCATION_LEN + 1))
            .is_err());
        assert!(AnnotatedFields::new()
            .with_notes("n".repeat(MAX_NOTES_LEN + 1))
            .is_err());
    }

    #[test]
    fn annotated_fields_count_characters_not_bytes() {
        // 100 three-byte characters: 300 bytes, but 100 characters, so valid.
        let value = "é".repeat(MAX_ANNOTATED_USER_LEN);
        assert!(value.len() > MAX_ANNOTATED_USER_LEN);
        assert!(AnnotatedFields::new().with_annotated_user(value).is_ok());
    }

    #[test]
    fn empty_annotated_fields_serialize_to_an_empty_object() {
        let json = serde_json::to_value(AnnotatedFields::new()).unwrap();
        assert_eq!(json, serde_json::json!({}));
        assert!(AnnotatedFields::new().is_empty());
    }
}
