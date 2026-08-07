//! Error classification, retry policy, and client-side rate limiting for the
//! Google Admin SDK.
//!
//! # Why classification dispatches on `reason`
//!
//! The Directory API returns **403 for rate limiting** (`reason:
//! rateLimitExceeded`) *and* 403 for a genuine permission failure. The HTTP
//! status alone cannot tell them apart, so nothing here ever calls
//! `error_for_status()`. Every non-2xx response has its body read and parsed
//! into Google's error envelope:
//!
//! ```json
//! {"error":{"code":403,
//!           "errors":[{"domain":"usageLimits","reason":"rateLimitExceeded"}],
//!           "status":"PERMISSION_DENIED"}}
//! ```
//!
//! Dispatch order is `error.errors[0].reason` → `error.status` → HTTP status,
//! and it fails closed: an unrecognised reason at 403 is treated as a
//! permission failure and surfaced verbatim. Giving up early on a real limit
//! costs a visibly slow sync; hammering a permission failure across 20,000
//! devices manufactures the storm the backoff exists to avoid.
//!
//! # Reads vs. writes
//!
//! Reads retry up to 8 attempts with full jitter. Writes retry up to 3, and
//! **only** on [`GoogleErrorClass::RateLimited`] or
//! [`GoogleErrorClass::AuthExpired`] — both of which are definitive
//! pre-execution rejections: Google answered and refused, so the mutation did
//! not happen. [`GoogleErrorClass::Ambiguous`] (a timeout, or a 5xx after the
//! request was sent) never auto-retries on a write; it surfaces to the caller,
//! which records it as an ambiguous item rather than guessing.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chalk_core::error::ChalkError;
use rand::Rng;
use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::token::TokenProvider;

/// Maximum attempts for a read operation (the first try plus 7 retries).
pub const DEFAULT_MAX_READ_ATTEMPTS: u32 = 8;

/// Maximum attempts for a write operation.
pub const DEFAULT_MAX_WRITE_ATTEMPTS: u32 = 3;

/// Base of the exponential schedule, in milliseconds.
pub const DEFAULT_BASE_DELAY_MS: u64 = 1_000;

/// Ceiling of the exponential schedule, in milliseconds.
pub const DEFAULT_MAX_DELAY_MS: u64 = 32_000;

/// Longest `Retry-After` we are willing to sleep for. Anything beyond this
/// aborts the run with a clear message: an invisible multi-minute stall is
/// worse than a clean failure.
pub const DEFAULT_RETRY_AFTER_CLAMP_SECS: u64 = 120;

/// Default client-side request budget, well under Google's per-project quota
/// because a district's other tooling shares the unraiseable per-account
/// ceiling.
pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 500;

/// How many times a single 401 may be recovered by invalidating the token and
/// retrying. A 401 is rejected at the auth edge before any mutation runs, so
/// this is safe on writes too.
const MAX_AUTH_RETRIES: u32 = 1;

/// Whether an operation mutates remote state. Drives which retry budget and
/// which set of retryable classes apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// A read. Retries broadly; repeating it cannot change remote state.
    Read,
    /// A write. Retries only on definitive pre-execution rejections.
    Write,
}

/// What Google's error response actually meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoogleErrorClass {
    /// Short-term rate limit. Retryable for both reads and writes.
    RateLimited {
        /// Server-supplied delay from the `Retry-After` header, if any.
        retry_after: Option<Duration>,
    },
    /// Server-side transient failure, or a transport failure that provably
    /// never reached Google. Retryable for reads.
    Transient,
    /// The request may or may not have been applied (timeout, or a failure
    /// after the request was sent). Never auto-retried.
    Ambiguous {
        /// What made the outcome unknowable.
        detail: String,
    },
    /// Genuine authorization failure — missing scope, missing domain-wide
    /// delegation, disabled API. Never retried.
    Permission {
        /// The `reason` Google returned, verbatim.
        reason: String,
    },
    /// The resource is already in the requested state (HTTP 412).
    PreconditionFailed,
    /// Malformed or rejected input. Never retried.
    Invalid {
        /// The `reason` Google returned, verbatim.
        reason: String,
    },
    /// The resource does not exist.
    NotFound,
    /// The access token was rejected. Triggers one invalidate-and-retry.
    AuthExpired,
    /// A long-window quota (daily) is exhausted. A 32-second cap cannot
    /// outwait a 24-hour quota, so this fails loudly instead of retrying.
    QuotaExhausted {
        /// The `reason` Google returned, verbatim.
        reason: String,
    },
}

impl fmt::Display for GoogleErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited { .. } => write!(f, "rate limited"),
            Self::Transient => write!(f, "transient"),
            Self::Ambiguous { detail } => write!(f, "ambiguous: {detail}"),
            Self::Permission { reason } => write!(f, "permission denied ({reason})"),
            Self::PreconditionFailed => write!(f, "precondition failed"),
            Self::Invalid { reason } => write!(f, "invalid request ({reason})"),
            Self::NotFound => write!(f, "not found"),
            Self::AuthExpired => write!(f, "auth expired"),
            Self::QuotaExhausted { reason } => write!(f, "quota exhausted ({reason})"),
        }
    }
}

impl GoogleErrorClass {
    /// True when repeating the request cannot make things worse and has a
    /// realistic chance of succeeding, for the given operation kind.
    pub fn is_retryable(&self, kind: OperationKind) -> bool {
        match kind {
            OperationKind::Read => matches!(
                self,
                Self::RateLimited { .. } | Self::Transient | Self::AuthExpired
            ),
            // A write retries only where Google definitively refused the
            // request before executing it.
            OperationKind::Write => matches!(self, Self::RateLimited { .. } | Self::AuthExpired),
        }
    }

    /// True when the failure should count against `throttle_events` in the
    /// sync-run record.
    pub fn is_throttle(&self) -> bool {
        matches!(self, Self::RateLimited { .. } | Self::QuotaExhausted { .. })
    }
}

/// A failed Google API call, carrying its classification.
#[derive(Debug, Clone)]
pub struct GoogleApiError {
    /// What the failure meant.
    pub class: GoogleErrorClass,
    /// HTTP status, absent for transport-level failures.
    pub status: Option<StatusCode>,
    /// The `reason` field from the error envelope, when present.
    pub reason: Option<String>,
    /// Human-readable detail from Google, or the raw body.
    pub message: String,
    /// The operation name supplied by the caller, e.g. `"list devices"`.
    pub operation: String,
    /// How many attempts were made in total.
    pub attempts: u32,
}

impl fmt::Display for GoogleApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed", self.operation)?;
        if self.attempts > 1 {
            write!(f, " after {} attempts", self.attempts)?;
        }
        match self.status {
            Some(s) => write!(f, " ({}): {}", s.as_u16(), self.class)?,
            None => write!(f, ": {}", self.class)?,
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for GoogleApiError {}

impl From<GoogleApiError> for ChalkError {
    fn from(e: GoogleApiError) -> Self {
        ChalkError::GoogleSync(e.to_string())
    }
}

/// Google's JSON error envelope.
#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    errors: Option<Vec<ErrorItem>>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorItem {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// Parsed pieces of a non-2xx response, before classification.
#[derive(Debug, Default)]
struct ParsedError {
    reason: Option<String>,
    canonical_status: Option<String>,
    message: Option<String>,
}

fn parse_envelope(body: &str) -> ParsedError {
    let Ok(env) = serde_json::from_str::<ErrorEnvelope>(body) else {
        return ParsedError::default();
    };
    let first = env.error.errors.as_ref().and_then(|v| v.first());
    ParsedError {
        reason: first.and_then(|e| e.reason.clone()),
        canonical_status: env.error.status.clone(),
        message: env
            .error
            .message
            .clone()
            .or_else(|| first.and_then(|e| e.message.clone())),
    }
}

/// Map a Google `reason` string to a class. `None` means "not recognised" and
/// sends the caller on to the canonical-status and HTTP-status fallbacks.
fn class_for_reason(reason: &str, retry_after: Option<Duration>) -> Option<GoogleErrorClass> {
    let r = reason.to_ascii_lowercase();
    let verbatim = reason.to_string();
    Some(match r.as_str() {
        // Retryable — short-window limits.
        "ratelimitexceeded" | "userratelimitexceeded" | "quotaexceeded" => {
            GoogleErrorClass::RateLimited { retry_after }
        }
        // Retryable — Google's own fault.
        "backenderror" | "internalerror" | "servererror" => GoogleErrorClass::Transient,
        // NOT retryable: a 32s cap cannot outwait a 24h quota. Fail loudly.
        "dailylimitexceeded" | "dailylimitexceededunreg" => {
            GoogleErrorClass::QuotaExhausted { reason: verbatim }
        }
        // NOT retryable: genuine authorization failure wearing a 403.
        "forbidden"
        | "insufficientpermissions"
        | "notauthorized"
        | "domaincannotuseapis"
        | "accessnotconfigured" => GoogleErrorClass::Permission { reason: verbatim },
        "conditionnotmet" => GoogleErrorClass::PreconditionFailed,
        "notfound" => GoogleErrorClass::NotFound,
        "invalid"
        | "invalidparameter"
        | "invalidvalue"
        | "required"
        | "badrequest"
        | "parseerror"
        | "duplicate"
        | "entityalreadyexists"
        | "conflict" => GoogleErrorClass::Invalid { reason: verbatim },
        _ => return None,
    })
}

/// Map Google's canonical status string (`PERMISSION_DENIED`, …) to a class.
fn class_for_canonical_status(
    status: &str,
    retry_after: Option<Duration>,
) -> Option<GoogleErrorClass> {
    Some(match status.to_ascii_uppercase().as_str() {
        "RESOURCE_EXHAUSTED" => GoogleErrorClass::RateLimited { retry_after },
        "UNAVAILABLE" | "INTERNAL" | "DEADLINE_EXCEEDED" => GoogleErrorClass::Transient,
        "PERMISSION_DENIED" => GoogleErrorClass::Permission {
            reason: status.to_string(),
        },
        "FAILED_PRECONDITION" => GoogleErrorClass::PreconditionFailed,
        "NOT_FOUND" => GoogleErrorClass::NotFound,
        "INVALID_ARGUMENT" | "ALREADY_EXISTS" => GoogleErrorClass::Invalid {
            reason: status.to_string(),
        },
        "UNAUTHENTICATED" => GoogleErrorClass::AuthExpired,
        _ => return None,
    })
}

/// Last-resort mapping from the HTTP status alone.
fn class_for_http_status(
    status: StatusCode,
    reason: Option<&str>,
    retry_after: Option<Duration>,
) -> GoogleErrorClass {
    // An unrecognised reason is reported verbatim so an operator can see the
    // string Google actually sent rather than our guess at it.
    let verbatim = reason
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".into());
    match status.as_u16() {
        401 => GoogleErrorClass::AuthExpired,
        // Fail closed: unknown reason at 403 is a permission failure.
        403 => GoogleErrorClass::Permission { reason: verbatim },
        404 => GoogleErrorClass::NotFound,
        412 => GoogleErrorClass::PreconditionFailed,
        429 => GoogleErrorClass::RateLimited { retry_after },
        500..=599 => GoogleErrorClass::Transient,
        _ => GoogleErrorClass::Invalid { reason: verbatim },
    }
}

/// Classify a non-2xx Google response.
///
/// Dispatch order is `errors[0].reason` → `error.status` → HTTP status, with
/// 401 short-circuited first because it is unambiguous and drives the
/// invalidate-and-retry path.
pub fn classify(
    status: StatusCode,
    headers: &HeaderMap,
    body: &str,
) -> (GoogleErrorClass, ParsedFields) {
    let retry_after = parse_retry_after(headers);
    let parsed = parse_envelope(body);

    let class = if status == StatusCode::UNAUTHORIZED {
        GoogleErrorClass::AuthExpired
    } else {
        parsed
            .reason
            .as_deref()
            .and_then(|r| class_for_reason(r, retry_after))
            .or_else(|| {
                parsed
                    .canonical_status
                    .as_deref()
                    .and_then(|s| class_for_canonical_status(s, retry_after))
            })
            .unwrap_or_else(|| class_for_http_status(status, parsed.reason.as_deref(), retry_after))
    };

    let message = parsed
        .message
        .clone()
        .unwrap_or_else(|| truncate_body(body));

    (
        class,
        ParsedFields {
            reason: parsed.reason,
            message,
        },
    )
}

/// The non-classification fields recovered from an error response.
#[derive(Debug, Clone)]
pub struct ParsedFields {
    /// The `reason` Google returned, when the envelope carried one.
    pub reason: Option<String>,
    /// A human-readable message, falling back to the (truncated) raw body.
    pub message: String,
}

/// Keep error strings loggable: Google can return kilobytes of HTML.
fn truncate_body(body: &str) -> String {
    const LIMIT: usize = 512;
    let trimmed = body.trim();
    if trimmed.chars().count() <= LIMIT {
        return trimmed.to_string();
    }
    let cut: String = trimmed.chars().take(LIMIT).collect();
    format!("{cut}…")
}

/// Parse `Retry-After` in both permitted forms: delta-seconds and HTTP-date.
pub fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    parse_retry_after_value(raw)
}

/// Parse a raw `Retry-After` header value.
pub fn parse_retry_after_value(raw: &str) -> Option<Duration> {
    parse_retry_after_at(raw, chrono::Utc::now())
}

/// Parse a raw `Retry-After` value against an explicit reference instant.
///
/// The HTTP-date form is relative to "now", so `now` is a parameter rather
/// than read from the clock: it makes the date arm exactly testable instead of
/// asserting against a tolerance window that a stalled machine can breach.
pub fn parse_retry_after_at(raw: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let raw = raw.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let when = chrono::DateTime::parse_from_rfc2822(raw)
        .map(|d| d.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            // RFC 7231 also permits the obsolete formats; the common one is an
            // RFC 1123 date with a literal `GMT` zone.
            chrono::NaiveDateTime::parse_from_str(
                raw.trim_end_matches(" GMT"),
                "%a, %d %b %Y %H:%M:%S",
            )
            .ok()
            .map(|n| n.and_utc())
        })?;
    let delta = when - now;
    Some(Duration::from_secs(delta.num_seconds().max(0) as u64))
}

/// What to do before the next attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextDelay {
    /// Sleep this long, then retry.
    Wait(Duration),
    /// Do not retry: give up now with this explanation.
    Abort(String),
}

/// Retry budgets and delay schedule.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    max_read_attempts: u32,
    max_write_attempts: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    retry_after_clamp: Duration,
    /// Test hook mirroring `webhooks::delivery::WebhookDeliveryEngine::with_backoff`:
    /// when set, replaces the computed jittered delays so tests never sleep.
    backoff_override_ms: Option<Vec<u64>>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_read_attempts: DEFAULT_MAX_READ_ATTEMPTS,
            max_write_attempts: DEFAULT_MAX_WRITE_ATTEMPTS,
            base_delay_ms: DEFAULT_BASE_DELAY_MS,
            max_delay_ms: DEFAULT_MAX_DELAY_MS,
            retry_after_clamp: Duration::from_secs(DEFAULT_RETRY_AFTER_CLAMP_SECS),
            backoff_override_ms: None,
        }
    }
}

impl RetryPolicy {
    /// The production policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// A policy with the same retry *counts* as production but zero delay, so
    /// test suites exercise the retry paths without ever sleeping.
    pub fn test_fast() -> Self {
        Self::default().with_backoff(vec![0; DEFAULT_MAX_READ_ATTEMPTS as usize])
    }

    /// Replace the computed backoff schedule. Entry `i` is the delay before
    /// retry `i + 1`; the last entry repeats if attempts outrun the schedule.
    /// An empty schedule leaves the computed delays in place.
    pub fn with_backoff(mut self, schedule_ms: Vec<u64>) -> Self {
        if !schedule_ms.is_empty() {
            self.backoff_override_ms = Some(schedule_ms);
        }
        self
    }

    /// Override the maximum attempt counts.
    pub fn with_max_attempts(mut self, read: u32, write: u32) -> Self {
        self.max_read_attempts = read.max(1);
        self.max_write_attempts = write.max(1);
        self
    }

    /// Override the `Retry-After` clamp.
    pub fn with_retry_after_clamp(mut self, clamp: Duration) -> Self {
        self.retry_after_clamp = clamp;
        self
    }

    /// Attempt budget for the given operation kind.
    pub fn max_attempts(&self, kind: OperationKind) -> u32 {
        match kind {
            OperationKind::Read => self.max_read_attempts,
            OperationKind::Write => self.max_write_attempts,
        }
    }

    /// The `Retry-After` clamp in force.
    pub fn retry_after_clamp(&self) -> Duration {
        self.retry_after_clamp
    }

    /// Decide how long to wait before retry number `retry_index` (0-based).
    ///
    /// A server-supplied `Retry-After` always overrides the computed delay. If
    /// it exceeds the clamp the run aborts rather than stalling invisibly.
    pub fn delay_for(&self, retry_index: u32, class: &GoogleErrorClass) -> NextDelay {
        if let GoogleErrorClass::RateLimited {
            retry_after: Some(d),
        } = class
        {
            if *d > self.retry_after_clamp {
                return NextDelay::Abort(format!(
                    "Google asked us to wait {}s, beyond the {}s limit — aborting rather than \
                     stalling. Retry once the quota window has reset.",
                    d.as_secs(),
                    self.retry_after_clamp.as_secs()
                ));
            }
            return NextDelay::Wait(*d);
        }

        if let Some(schedule) = &self.backoff_override_ms {
            let idx = (retry_index as usize).min(schedule.len() - 1);
            return NextDelay::Wait(Duration::from_millis(schedule[idx]));
        }

        NextDelay::Wait(Duration::from_millis(self.jittered_delay_ms(retry_index)))
    }

    /// Full jitter: `rand(0, min(cap, base * 2^n))`.
    fn jittered_delay_ms(&self, retry_index: u32) -> u64 {
        let ceiling = self
            .base_delay_ms
            .saturating_mul(1u64 << retry_index.min(20))
            .min(self.max_delay_ms);
        rand::rng().random_range(0..=ceiling)
    }
}

/// Client-side token bucket shared by every call site on a client.
///
/// Deliberately one bucket per client rather than per call site: per-call-site
/// configuration is how throttling ends up tuned differently on the read and
/// write paths, with the write path invariably the worse of the two.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// A bucket permitting `n` requests per minute, with a full-minute burst.
    pub fn per_minute(n: u32) -> Self {
        let capacity = f64::from(n.max(1));
        Self {
            capacity,
            refill_per_sec: capacity / 60.0,
            state: Mutex::new(BucketState {
                tokens: capacity,
                last: Instant::now(),
            }),
        }
    }

    /// A bucket that never delays. For tests and for callers doing their own
    /// pacing.
    pub fn unlimited() -> Self {
        Self {
            capacity: f64::MAX,
            refill_per_sec: f64::MAX,
            state: Mutex::new(BucketState {
                tokens: f64::MAX,
                last: Instant::now(),
            }),
        }
    }

    /// Consume one token, waiting if the bucket is empty.
    pub async fn acquire(&self) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(state.last).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        state.last = now;

        if state.tokens < 1.0 {
            let wait = (1.0 - state.tokens) / self.refill_per_sec;
            drop(state);
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
            let mut state = self.state.lock().await;
            state.tokens = 0.0;
            state.last = Instant::now();
            return;
        }

        state.tokens -= 1.0;
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::per_minute(DEFAULT_REQUESTS_PER_MINUTE)
    }
}

/// Drives a single Google API call to completion: paces it through the shared
/// token bucket, attaches a freshly resolved bearer token, classifies any
/// failure, and retries within the policy.
#[derive(Debug, Clone)]
pub struct RetryExecutor {
    auth: Arc<dyn TokenProvider>,
    policy: RetryPolicy,
    limiter: Arc<RateLimiter>,
    throttle_events: Arc<AtomicU64>,
}

impl RetryExecutor {
    /// Build an executor over a token provider, with production defaults.
    pub fn new(auth: Arc<dyn TokenProvider>) -> Self {
        Self {
            auth,
            policy: RetryPolicy::default(),
            limiter: Arc::new(RateLimiter::default()),
            throttle_events: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Replace the retry policy.
    pub fn with_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Replace the shared rate limiter.
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.limiter = Arc::new(limiter);
        self
    }

    /// The token provider backing this executor.
    pub fn auth(&self) -> &Arc<dyn TokenProvider> {
        &self.auth
    }

    /// The active retry policy.
    pub fn policy(&self) -> &RetryPolicy {
        &self.policy
    }

    /// Number of throttle events observed, for
    /// `google_device_sync_runs.throttle_events`.
    pub fn throttle_events(&self) -> u64 {
        self.throttle_events.load(Ordering::Relaxed)
    }

    /// Execute a request, retrying per policy.
    ///
    /// `build` is called once per attempt and must return a fresh
    /// `RequestBuilder`; the executor attaches the bearer token itself, so the
    /// closure never sees or caches a token.
    pub async fn execute<F>(
        &self,
        kind: OperationKind,
        operation: &str,
        build: F,
    ) -> Result<reqwest::Response, GoogleApiError>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let max_attempts = self.policy.max_attempts(kind);
        let mut auth_retries = 0u32;
        let mut retry_index = 0u32;
        let mut attempts = 0u32;

        loop {
            self.limiter.acquire().await;
            attempts += 1;

            let token = self.auth.token().await.map_err(|e| GoogleApiError {
                class: GoogleErrorClass::AuthExpired,
                status: None,
                reason: None,
                message: e.to_string(),
                operation: operation.to_string(),
                attempts,
            })?;

            let outcome = build().bearer_auth(token).send().await;

            let (class, fields, status) = match outcome {
                Ok(resp) if resp.status().is_success() => return Ok(resp),
                Ok(resp) => {
                    let status = resp.status();
                    let headers = resp.headers().clone();
                    let body = resp.text().await.unwrap_or_default();
                    let (class, fields) = classify(status, &headers, &body);
                    (class, fields, Some(status))
                }
                Err(e) => {
                    let class = transport_error_class(&e, kind);
                    (
                        class,
                        ParsedFields {
                            reason: None,
                            message: e.to_string(),
                        },
                        None,
                    )
                }
            };

            if class.is_throttle() {
                self.throttle_events.fetch_add(1, Ordering::Relaxed);
            }

            let give_up = |attempts: u32, note: Option<String>| GoogleApiError {
                class: class.clone(),
                status,
                reason: fields.reason.clone(),
                message: match note {
                    Some(n) => format!("{} [{}]", fields.message, n),
                    None => fields.message.clone(),
                },
                operation: operation.to_string(),
                attempts,
            };

            // A 401 is rejected at the auth edge before any mutation runs, so
            // recovering it is safe even on writes. It is recoverable *only*
            // this way: a second 401 on a freshly minted token is a real
            // credential problem, and burning the remaining attempts on it
            // would just delay the same failure.
            if class == GoogleErrorClass::AuthExpired {
                if auth_retries < MAX_AUTH_RETRIES {
                    auth_retries += 1;
                    self.auth.invalidate().await;
                    debug!(operation, "token rejected; invalidated and retrying once");
                    continue;
                }
                return Err(give_up(attempts, None));
            }

            if !class.is_retryable(kind) || attempts >= max_attempts {
                return Err(give_up(attempts, None));
            }

            match self.policy.delay_for(retry_index, &class) {
                NextDelay::Abort(why) => return Err(give_up(attempts, Some(why))),
                NextDelay::Wait(d) => {
                    warn!(
                        operation,
                        attempt = attempts,
                        delay_ms = d.as_millis() as u64,
                        class = %class,
                        "Google API call failed; retrying"
                    );
                    retry_index += 1;
                    if !d.is_zero() {
                        tokio::time::sleep(d).await;
                    }
                }
            }
        }
    }
}

/// Classify a transport-level failure.
///
/// A connect failure provably never reached Google, so it is transient rather
/// than ambiguous. A timeout or a failure mid-response may have been applied,
/// which matters only for writes — for reads, repeating is harmless.
fn transport_error_class(e: &reqwest::Error, kind: OperationKind) -> GoogleErrorClass {
    if e.is_connect() || kind == OperationKind::Read {
        GoogleErrorClass::Transient
    } else {
        GoogleErrorClass::Ambiguous {
            detail: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::tests::CountingTokenProvider;
    use crate::token::StaticTokenProvider;
    use std::sync::atomic::Ordering as AtomicOrdering;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn google_error(code: u16, reason: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": code,
                "message": message,
                "errors": [{"domain": "usageLimits", "reason": reason, "message": message}],
            }
        })
    }

    fn classify_json(status: u16, body: &serde_json::Value) -> GoogleErrorClass {
        classify(
            StatusCode::from_u16(status).unwrap(),
            &HeaderMap::new(),
            &body.to_string(),
        )
        .0
    }

    // ---- classification table -------------------------------------------

    #[test]
    fn rate_limit_reasons_at_403_are_rate_limited() {
        for reason in [
            "rateLimitExceeded",
            "userRateLimitExceeded",
            "quotaExceeded",
        ] {
            let class = classify_json(403, &google_error(403, reason, "slow down"));
            assert!(
                matches!(class, GoogleErrorClass::RateLimited { .. }),
                "{reason} classified as {class}"
            );
            assert!(class.is_retryable(OperationKind::Read));
            assert!(class.is_retryable(OperationKind::Write));
        }
    }

    #[test]
    fn permission_reasons_at_403_are_not_retryable() {
        for reason in [
            "forbidden",
            "insufficientPermissions",
            "notAuthorized",
            "domainCannotUseApis",
        ] {
            let class = classify_json(403, &google_error(403, reason, "nope"));
            assert!(
                matches!(class, GoogleErrorClass::Permission { .. }),
                "{reason} classified as {class}"
            );
            assert!(!class.is_retryable(OperationKind::Read));
            assert!(!class.is_retryable(OperationKind::Write));
        }
    }

    #[test]
    fn daily_limit_exceeded_is_never_retried() {
        let class = classify_json(403, &google_error(403, "dailyLimitExceeded", "daily quota"));
        assert!(matches!(class, GoogleErrorClass::QuotaExhausted { .. }));
        assert!(!class.is_retryable(OperationKind::Read));
        assert!(!class.is_retryable(OperationKind::Write));
    }

    #[test]
    fn unknown_reason_at_403_fails_closed_and_is_surfaced_verbatim() {
        let class = classify_json(403, &google_error(403, "somethingBrandNew", "unrecognised"));
        match class {
            GoogleErrorClass::Permission { ref reason } => {
                assert_eq!(reason, "somethingBrandNew")
            }
            other => panic!("expected Permission, got {other}"),
        }
        assert!(!class.is_retryable(OperationKind::Read));
    }

    #[test]
    fn backend_and_internal_errors_are_transient() {
        for reason in ["backendError", "internalError"] {
            let class = classify_json(500, &google_error(500, reason, "oops"));
            assert_eq!(class, GoogleErrorClass::Transient);
            assert!(class.is_retryable(OperationKind::Read));
            // A write never auto-retries a transient failure.
            assert!(!class.is_retryable(OperationKind::Write));
        }
    }

    #[test]
    fn status_specific_classes() {
        assert_eq!(
            classify_json(401, &google_error(401, "authError", "expired")),
            GoogleErrorClass::AuthExpired
        );
        assert_eq!(
            classify_json(412, &google_error(412, "conditionNotMet", "already")),
            GoogleErrorClass::PreconditionFailed
        );
        assert_eq!(
            classify_json(404, &google_error(404, "notFound", "gone")),
            GoogleErrorClass::NotFound
        );
        assert!(matches!(
            classify_json(409, &google_error(409, "duplicate", "exists")),
            GoogleErrorClass::Invalid { .. }
        ));
    }

    #[test]
    fn canonical_status_is_the_second_dispatch_step() {
        let body = serde_json::json!({
            "error": {"code": 403, "message": "denied", "status": "RESOURCE_EXHAUSTED"}
        });
        assert!(matches!(
            classify_json(403, &body),
            GoogleErrorClass::RateLimited { .. }
        ));

        let body = serde_json::json!({
            "error": {"code": 403, "message": "denied", "status": "PERMISSION_DENIED"}
        });
        assert!(matches!(
            classify_json(403, &body),
            GoogleErrorClass::Permission { .. }
        ));
    }

    #[test]
    fn non_json_body_falls_back_to_http_status() {
        let class = classify(
            StatusCode::INTERNAL_SERVER_ERROR,
            &HeaderMap::new(),
            "<html>500</html>",
        );
        assert_eq!(class.0, GoogleErrorClass::Transient);
        assert_eq!(class.1.message, "<html>500</html>");

        // A bare 403 with no parseable body still fails closed.
        let class = classify(StatusCode::FORBIDDEN, &HeaderMap::new(), "nope");
        assert!(matches!(class.0, GoogleErrorClass::Permission { .. }));
    }

    #[test]
    fn long_bodies_are_truncated() {
        let body = "x".repeat(2000);
        let (_, fields) = classify(StatusCode::BAD_GATEWAY, &HeaderMap::new(), &body);
        assert!(fields.message.chars().count() <= 513);
        assert!(fields.message.ends_with('…'));
    }

    // ---- Retry-After ------------------------------------------------------

    #[test]
    fn retry_after_delta_seconds_is_parsed() {
        assert_eq!(parse_retry_after_value("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after_value(" 5 "), Some(Duration::from_secs(5)));
    }

    /// A fixed reference instant, so the HTTP-date arm is exact rather than
    /// asserted against a tolerance window that a stalled machine can breach.
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-07-25T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn retry_after_http_date_is_parsed() {
        let now = fixed_now();
        let formatted = (now + chrono::Duration::seconds(45))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        assert_eq!(
            parse_retry_after_at(&formatted, now),
            Some(Duration::from_secs(45)),
            "parsing {formatted}"
        );
    }

    #[test]
    fn retry_after_rfc2822_offset_form_is_parsed() {
        let now = fixed_now();
        let formatted = (now + chrono::Duration::seconds(90)).to_rfc2822();
        assert_eq!(
            parse_retry_after_at(&formatted, now),
            Some(Duration::from_secs(90)),
            "parsing {formatted}"
        );
    }

    #[test]
    fn retry_after_past_http_date_is_zero_not_negative() {
        let now = fixed_now();
        let formatted = (now - chrono::Duration::seconds(45))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        assert_eq!(
            parse_retry_after_at(&formatted, now),
            Some(Duration::from_secs(0))
        );
    }

    #[test]
    fn retry_after_header_is_read_from_response_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "12".parse().unwrap());
        let (class, _) = classify(
            StatusCode::TOO_MANY_REQUESTS,
            &headers,
            &google_error(429, "rateLimitExceeded", "slow").to_string(),
        );
        assert_eq!(
            class,
            GoogleErrorClass::RateLimited {
                retry_after: Some(Duration::from_secs(12))
            }
        );
    }

    #[test]
    fn retry_after_garbage_is_ignored() {
        assert_eq!(parse_retry_after_value("soon"), None);
    }

    #[test]
    fn retry_after_overrides_the_computed_delay() {
        let policy = RetryPolicy::default();
        let class = GoogleErrorClass::RateLimited {
            retry_after: Some(Duration::from_secs(7)),
        };
        assert_eq!(
            policy.delay_for(0, &class),
            NextDelay::Wait(Duration::from_secs(7))
        );
    }

    #[test]
    fn retry_after_beyond_the_clamp_aborts_rather_than_sleeping() {
        let policy = RetryPolicy::default();
        let class = GoogleErrorClass::RateLimited {
            retry_after: Some(Duration::from_secs(900)),
        };
        match policy.delay_for(0, &class) {
            NextDelay::Abort(why) => {
                assert!(why.contains("900"), "{why}");
                assert!(why.contains("120"), "{why}");
            }
            other => panic!("expected abort, got {other:?}"),
        }
    }

    // ---- delay schedule ---------------------------------------------------

    #[test]
    fn full_jitter_stays_within_the_capped_exponential_window() {
        let policy = RetryPolicy::default();
        for retry_index in 0..10u32 {
            let ceiling = (DEFAULT_BASE_DELAY_MS << retry_index.min(20)).min(DEFAULT_MAX_DELAY_MS);
            for _ in 0..50 {
                let ms = policy.jittered_delay_ms(retry_index);
                assert!(ms <= ceiling, "{ms} > {ceiling} at retry {retry_index}");
            }
        }
    }

    #[test]
    fn backoff_override_replaces_computed_delays_and_saturates() {
        let policy = RetryPolicy::default().with_backoff(vec![5, 10]);
        assert_eq!(
            policy.delay_for(0, &GoogleErrorClass::Transient),
            NextDelay::Wait(Duration::from_millis(5))
        );
        assert_eq!(
            policy.delay_for(1, &GoogleErrorClass::Transient),
            NextDelay::Wait(Duration::from_millis(10))
        );
        assert_eq!(
            policy.delay_for(9, &GoogleErrorClass::Transient),
            NextDelay::Wait(Duration::from_millis(10))
        );
    }

    #[test]
    fn empty_backoff_override_is_ignored() {
        let policy = RetryPolicy::default().with_backoff(vec![]);
        assert!(matches!(
            policy.delay_for(0, &GoogleErrorClass::Transient),
            NextDelay::Wait(_)
        ));
    }

    #[test]
    fn attempt_budgets_differ_by_operation_kind() {
        let policy = RetryPolicy::default();
        assert_eq!(
            policy.max_attempts(OperationKind::Read),
            DEFAULT_MAX_READ_ATTEMPTS
        );
        assert_eq!(
            policy.max_attempts(OperationKind::Write),
            DEFAULT_MAX_WRITE_ATTEMPTS
        );
    }

    // ---- executor ---------------------------------------------------------

    fn executor(auth: Arc<dyn TokenProvider>) -> RetryExecutor {
        RetryExecutor::new(auth)
            .with_policy(RetryPolicy::test_fast())
            .with_rate_limiter(RateLimiter::unlimited())
    }

    fn static_executor() -> RetryExecutor {
        executor(Arc::new(StaticTokenProvider::new("t")))
    }

    async fn mount_error(server: &MockServer, verb: &str, status: u16, reason: &str) {
        Mock::given(method(verb))
            .and(path("/x"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(google_error(status, reason, "detail")),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn read_retries_rate_limit_until_the_budget_is_spent() {
        let server = MockServer::start().await;
        mount_error(&server, "GET", 403, "rateLimitExceeded").await;
        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());

        let err = static_executor()
            .execute(OperationKind::Read, "list devices", || http.get(&url))
            .await
            .unwrap_err();

        assert!(matches!(err.class, GoogleErrorClass::RateLimited { .. }));
        assert_eq!(err.attempts, DEFAULT_MAX_READ_ATTEMPTS);
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            DEFAULT_MAX_READ_ATTEMPTS as usize
        );
    }

    #[tokio::test]
    async fn read_does_not_retry_a_permission_failure() {
        let server = MockServer::start().await;
        mount_error(&server, "GET", 403, "forbidden").await;
        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());

        let err = static_executor()
            .execute(OperationKind::Read, "list devices", || http.get(&url))
            .await
            .unwrap_err();

        assert!(matches!(err.class, GoogleErrorClass::Permission { .. }));
        assert_eq!(err.attempts, 1);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn read_fails_immediately_on_daily_limit_exceeded() {
        let server = MockServer::start().await;
        mount_error(&server, "GET", 403, "dailyLimitExceeded").await;
        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());

        let exec = static_executor();
        let err = exec
            .execute(OperationKind::Read, "list devices", || http.get(&url))
            .await
            .unwrap_err();

        assert!(matches!(err.class, GoogleErrorClass::QuotaExhausted { .. }));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(exec.throttle_events(), 1);
    }

    #[tokio::test]
    async fn read_recovers_when_the_limit_clears() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(403).set_body_json(google_error(
                403,
                "rateLimitExceeded",
                "slow",
            )))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());
        let exec = static_executor();
        let resp = exec
            .execute(OperationKind::Read, "list devices", || http.get(&url))
            .await
            .expect("should succeed once the limit clears");

        assert!(resp.status().is_success());
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
        assert_eq!(exec.throttle_events(), 2);
    }

    #[tokio::test]
    async fn write_retries_a_definitive_rate_limit() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(429).set_body_json(google_error(
                429,
                "rateLimitExceeded",
                "slow",
            )))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());
        let resp = static_executor()
            .execute(OperationKind::Write, "move devices", || http.post(&url))
            .await
            .expect("a rate limit is a pre-execution rejection and is safe to retry");

        assert!(resp.status().is_success());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn write_does_not_retry_a_transient_server_error() {
        let server = MockServer::start().await;
        mount_error(&server, "POST", 500, "backendError").await;
        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());

        let err = static_executor()
            .execute(OperationKind::Write, "move devices", || http.post(&url))
            .await
            .unwrap_err();

        assert_eq!(err.class, GoogleErrorClass::Transient);
        assert_eq!(err.attempts, 1);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn write_does_not_retry_an_ambiguous_transport_failure() {
        // Nothing listens on this port, but the classifier is what matters:
        // an ambiguous outcome must never be retried on a write.
        let ambiguous = GoogleErrorClass::Ambiguous {
            detail: "timed out".to_string(),
        };
        assert!(!ambiguous.is_retryable(OperationKind::Write));
        assert!(!ambiguous.is_retryable(OperationKind::Read));
    }

    #[tokio::test]
    async fn write_aborts_when_retry_after_exceeds_the_clamp() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/x"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "900")
                    .set_body_json(google_error(429, "rateLimitExceeded", "slow")),
            )
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());
        let started = Instant::now();
        let err = static_executor()
            .execute(OperationKind::Write, "move devices", || http.post(&url))
            .await
            .unwrap_err();

        assert!(err.message.contains("aborting"), "{}", err.message);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must abort, not sleep"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unauthorized_invalidates_the_token_and_retries_exactly_once() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(401).set_body_json(google_error(
                401,
                "authError",
                "expired",
            )))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let auth = Arc::new(CountingTokenProvider::default());
        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());

        let resp = executor(auth.clone())
            .execute(OperationKind::Read, "list devices", || http.get(&url))
            .await
            .expect("a refreshed token should succeed");

        assert!(resp.status().is_success());
        assert_eq!(auth.invalidations.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(auth.tokens_issued.load(AtomicOrdering::SeqCst), 2);
    }

    #[tokio::test]
    async fn persistent_unauthorized_gives_up_after_one_refresh() {
        let server = MockServer::start().await;
        mount_error(&server, "POST", 401, "authError").await;

        let auth = Arc::new(CountingTokenProvider::default());
        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());

        let err = executor(auth.clone())
            .execute(OperationKind::Write, "move devices", || http.post(&url))
            .await
            .unwrap_err();

        assert_eq!(err.class, GoogleErrorClass::AuthExpired);
        assert_eq!(auth.invalidations.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn success_returns_the_response_untouched() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"a": 1})))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/x", server.uri());
        let resp = static_executor()
            .execute(OperationKind::Read, "get", || http.get(&url))
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["a"], 1);
    }

    /// Runs on tokio's paused clock: virtual time advances only when the
    /// runtime parks on a timer, so "did this wait?" is answered exactly
    /// rather than by measuring wall clock on a loaded machine.
    #[tokio::test(start_paused = true)]
    async fn rate_limiter_bursts_to_capacity_then_paces() {
        let limiter = RateLimiter::per_minute(60);
        let started = tokio::time::Instant::now();

        // The bucket starts full, so a full minute's budget is immediate.
        for _ in 0..60 {
            limiter.acquire().await;
        }
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "a burst up to capacity must not sleep"
        );

        // The next one has to wait for a token to refill — one per second at
        // this rate.
        limiter.acquire().await;
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(1),
            "past capacity the limiter must pace requests"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unlimited_rate_limiter_never_waits() {
        let limiter = RateLimiter::unlimited();
        let started = tokio::time::Instant::now();
        for _ in 0..1000 {
            limiter.acquire().await;
        }
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[test]
    fn error_display_includes_status_and_operation() {
        let err = GoogleApiError {
            class: GoogleErrorClass::Permission {
                reason: "forbidden".to_string(),
            },
            status: Some(StatusCode::FORBIDDEN),
            reason: Some("forbidden".to_string()),
            message: "Not Authorized to access this resource".to_string(),
            operation: "list devices".to_string(),
            attempts: 1,
        };
        let s = err.to_string();
        assert!(s.contains("list devices"), "{s}");
        assert!(s.contains("403"), "{s}");
        assert!(s.contains("forbidden"), "{s}");

        let chalk: ChalkError = err.into();
        assert!(chalk.to_string().contains("Google Sync error"));
    }

    #[test]
    fn terminal_classes_are_never_retried() {
        for class in [
            GoogleErrorClass::NotFound,
            GoogleErrorClass::PreconditionFailed,
            GoogleErrorClass::Invalid {
                reason: "invalid".into(),
            },
            GoogleErrorClass::Ambiguous {
                detail: "timed out".into(),
            },
            GoogleErrorClass::QuotaExhausted {
                reason: "dailyLimitExceeded".into(),
            },
        ] {
            assert!(!class.is_retryable(OperationKind::Read), "{class}");
            assert!(!class.is_retryable(OperationKind::Write), "{class}");
        }
    }
}
