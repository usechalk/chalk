//! TOML-based configuration system for Chalk.

use crate::error::{ChalkError, Result};
use crate::webhooks::models::{WebhookMode, WebhookSecurityMode};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level Chalk configuration, deserialized from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChalkConfig {
    pub chalk: ChalkSection,
    #[serde(default)]
    pub sis: SisConfig,
    #[serde(default)]
    pub idp: IdpConfig,
    #[serde(default)]
    pub google_sync: GoogleSyncConfig,
    #[serde(default)]
    pub device_sync: DeviceSyncConfig,
    #[serde(default)]
    pub ad_sync: AdSyncConfig,
    /// Non-Google MDM connectors (WS-14): Intune for Windows, Jamf for iPad.
    #[serde(default)]
    pub mdm: MdmConfig,
    /// Entra ID (Azure AD) user provisioning (WS-15b).
    #[serde(default)]
    pub entra: EntraConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub modules: ModulesConfig,
    #[serde(default)]
    pub marketplace: MarketplaceConfig,
    #[serde(default)]
    pub helpdesk: HelpdeskConfig,
    /// Outbound mail. Absent means Chalk sends none — see [`crate::mail`].
    #[serde(default)]
    pub mail: Option<crate::mail::SmtpConfig>,
    #[serde(default)]
    pub sso_partners: Vec<SsoPartnerConfig>,
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
}

/// Which product modules this deployment offers.
///
/// # Self-host is never gated
///
/// Every module defaults to **on**, and a self-hosted operator can turn one off
/// to tidy their nav but is never restricted by us (D2). The flags exist for
/// the hosted control plane, which writes them per tenant from that tenant's
/// plan — the entitlement flow in ARCHITECTURE §8.2 ends here.
///
/// # Off means gone, not hidden
///
/// A disabled module's routes return 404. Hiding the nav link alone would be a
/// suggestion rather than a control, and the URL is guessable — `/devices` is
/// not a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModulesConfig {
    /// Device inventory, Google device sync, change sets.
    #[serde(default = "enabled")]
    pub devices: bool,
    /// Tickets, the teacher portal, email ingestion.
    #[serde(default = "enabled")]
    pub helpdesk: bool,
    /// Chalk serving identity **outward**: the SAML IdP, OIDC federation, the
    /// launcher portal, Clever/ClassLink compatibility, the OneRoster API, and
    /// Google Workspace / Active Directory provisioning.
    ///
    /// **Not roster ingestion.** The SIS connection that populates Chalk's own
    /// database stays on in every tier, because the device inventory and the
    /// helpdesk are built on that roster — gating it would break the two
    /// modules this one is supposed to be independent of. The published
    /// pricing draws exactly this line and names it the question most likely
    /// to be argued at contract time: *the connection that populates your
    /// device and ticket data is included; Chalk serving rostering, SSO and
    /// provisioning to the rest of your district is Full stack.*
    ///
    /// On by default, so self-host keeps everything and no existing install
    /// loses a surface on upgrade.
    #[serde(default = "enabled")]
    pub roster_sso: bool,
    /// Asset types this deployment may create, as `AssetType` values.
    ///
    /// Empty means unrestricted, which is the self-host default and D2's
    /// promise. The hosted free tier sets `["chromebook"]` — D8, and the only
    /// thing that gates it. Enforced wherever an asset is created, never
    /// compiled out, because a check that only exists in one build is a check
    /// that will be missing from the other.
    #[serde(default)]
    pub asset_types_allowed: Vec<String>,
}

fn enabled() -> bool {
    true
}

impl Default for ModulesConfig {
    fn default() -> Self {
        Self {
            devices: true,
            helpdesk: true,
            roster_sso: true,
            asset_types_allowed: Vec::new(),
        }
    }
}

impl ModulesConfig {
    /// Whether this deployment may hold an asset of this type.
    ///
    /// An empty allow-list permits everything. A non-empty one is matched on
    /// the stable `as_str` value, not the display name.
    pub fn allows_asset_type(&self, asset_type: crate::models::asset::AssetType) -> bool {
        self.asset_types_allowed.is_empty()
            || self
                .asset_types_allowed
                .iter()
                .any(|t| t == asset_type.as_str())
    }

    /// What to tell someone whose asset type is not permitted.
    ///
    /// Names both the type they tried and what the plan covers, because "not
    /// permitted" without either is a dead end — and on the free tier the fix
    /// is a purchase decision, which nobody makes from an error they cannot
    /// parse.
    ///
    /// Deliberately avoids an indefinite article. The type is a bare enum
    /// value, so "a {type}" produced "a other" — and picking a/an from the
    /// first letter would still say "a hotspot" beside "an other". Naming the
    /// value in quotes sidesteps the grammar entirely and reads as the literal
    /// it is.
    pub fn asset_type_refusal(&self, asset_type: crate::models::asset::AssetType) -> String {
        format!(
            "This plan covers only these device types: {}. \"{}\" is not one of \
             them. Upgrading lifts the restriction.",
            self.asset_types_allowed.join(", "),
            asset_type.as_str()
        )
    }
}

/// Core Chalk instance settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChalkSection {
    pub instance_name: String,
    pub data_dir: String,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub admin_password_hash: Option<String>,
    /// Where operational alerts go (low stock, GP-4). Optional: absent means
    /// alerts stay on-screen only, which is also what happens with no mailer.
    #[serde(default)]
    pub alerts_email: Option<String>,
    /// Send the fleet-digest email to `alerts_email` once a day (GP-5).
    #[serde(default)]
    pub daily_digest: bool,
}

/// Database backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "DatabaseDriver::default_driver")]
    pub driver: DatabaseDriver,
    /// SQLite file path (used when driver = "sqlite").
    #[serde(default)]
    pub path: Option<String>,
    /// PostgreSQL connection URL (used when driver = "postgres").
    #[serde(default)]
    pub url: Option<String>,
    /// PostgreSQL schema name (required when driver = "postgres"). Must match
    /// `^[a-z][a-z0-9_]{2,40}$` to safely interpolate into DDL/search_path.
    #[serde(default)]
    pub schema: Option<String>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            driver: DatabaseDriver::Sqlite,
            path: Some("/var/lib/chalk/chalk.db".into()),
            url: None,
            schema: None,
        }
    }
}

/// Supported database drivers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseDriver {
    Sqlite,
    Postgres,
}

impl DatabaseDriver {
    fn default_driver() -> Self {
        Self::Sqlite
    }
}

/// Returns true if `s` is a safe Postgres schema identifier:
/// starts with a lowercase letter, contains only lowercase ASCII alphanumerics
/// and underscores, length 3..=41.
pub fn is_valid_pg_schema(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes.len() > 41 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// SIS (Student Information System) integration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SisConfig {
    #[serde(default)]
    pub enabled: bool,
    /// SIS provider. `None` means the tenant has not chosen a provider yet —
    /// this is the new default in 1.4 onward. Pre-1.4 TOML that omitted this
    /// key silently meant PowerSchool; that implicit default has been
    /// removed. See `CHANGELOG.md` for the breaking-change note.
    #[serde(default, deserialize_with = "deserialize_optional_sis_provider")]
    pub provider: Option<SisProvider>,
    #[serde(default)]
    pub base_url: String,
    /// OAuth 2.0 token endpoint URL. Required for Infinite Campus and Skyward
    /// (their token URL is not derivable from base_url). Optional for PowerSchool.
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default = "default_sync_schedule")]
    pub sync_schedule: String,
    /// Filesystem path to a OneRoster 1.1 CSV bundle (directory). Required when
    /// `provider = "oneroster_csv"`; ignored otherwise. The directory should
    /// contain orgs.csv / users.csv / classes.csv / etc. plus an optional
    /// manifest.csv selecting which files to load.
    #[serde(default)]
    pub csv_dir: Option<String>,
}

/// Custom deserializer for `SisConfig::provider` that accepts a bare string
/// (e.g. `provider = "powerschool"`) and treats a missing key or `null` as
/// `None`. The default `Option<T>` serde deserializer already handles `null`
/// and missing keys; we use this wrapper so we can keep the field a string in
/// TOML (rather than forcing operators to write a tagged enum) while changing
/// the in-memory default from `PowerSchool` to `None`.
fn deserialize_optional_sis_provider<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SisProvider>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<SisProvider> = Option::deserialize(deserializer)?;
    Ok(opt)
}

impl Default for SisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: None,
            base_url: String::new(),
            token_url: None,
            client_id: String::new(),
            client_secret: String::new(),
            sync_schedule: default_sync_schedule(),
            csv_dir: None,
        }
    }
}

fn default_sync_schedule() -> String {
    "0 2 * * *".into()
}

/// Supported SIS providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SisProvider {
    #[serde(rename = "powerschool")]
    PowerSchool,
    #[serde(rename = "infinite_campus")]
    InfiniteCampus,
    #[serde(rename = "skyward")]
    Skyward,
    /// Filesystem-backed source: read a OneRoster 1.1 CSV bundle from a
    /// directory on disk. Uses `sis.csv_dir` instead of the OAuth fields.
    #[serde(rename = "oneroster_csv")]
    OneRosterCsv,
}

impl SisProvider {
    /// Stable on-the-wire identifier — the same string the serde rename emits
    /// and that the hosted DB / signup form / import-toml CLI all agree on.
    /// Keep this in lockstep with the `#[serde(rename = …)]` attributes above.
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::PowerSchool => "powerschool",
            Self::InfiniteCampus => "infinite_campus",
            Self::Skyward => "skyward",
            Self::OneRosterCsv => "oneroster_csv",
        }
    }

    /// Inverse of [`wire_name`]. Returns `None` for unknown strings.
    pub fn from_wire_name(s: &str) -> Option<Self> {
        match s {
            "powerschool" => Some(Self::PowerSchool),
            "infinite_campus" => Some(Self::InfiniteCampus),
            "skyward" => Some(Self::Skyward),
            "oneroster_csv" => Some(Self::OneRosterCsv),
            _ => None,
        }
    }
}

/// Identity Provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub qr_badge_login: bool,
    #[serde(default)]
    pub picture_passwords: bool,
    #[serde(default)]
    pub saml_cert_path: Option<String>,
    #[serde(default)]
    pub saml_key_path: Option<String>,
    #[serde(default = "default_session_timeout")]
    pub session_timeout_minutes: u32,
    /// Pattern for generating default user passwords (e.g., `"{lastName}{birthYear}"`).
    #[serde(default)]
    pub default_password_pattern: Option<String>,
    /// Roles to auto-generate passwords for (e.g., `["student", "teacher"]`).
    #[serde(default)]
    pub default_password_roles: Vec<String>,
    #[serde(default)]
    pub google: Option<IdpGoogleConfig>,
}

impl Default for IdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            qr_badge_login: false,
            picture_passwords: false,
            saml_cert_path: None,
            saml_key_path: None,
            session_timeout_minutes: default_session_timeout(),
            default_password_pattern: None,
            default_password_roles: Vec::new(),
            google: None,
        }
    }
}

fn default_session_timeout() -> u32 {
    480
}

/// Google Workspace SAML integration settings for IDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpGoogleConfig {
    pub workspace_domain: String,
    pub google_acs_url: String,
    pub google_entity_id: String,
}

/// Google Workspace sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GoogleSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provision_users: bool,
    #[serde(default)]
    pub manage_ous: bool,
    #[serde(default)]
    pub suspend_inactive: bool,
    #[serde(default = "default_sync_schedule")]
    pub sync_schedule: String,
    #[serde(default)]
    pub service_account_key_path: Option<String>,
    #[serde(default)]
    pub admin_email: Option<String>,
    #[serde(default)]
    pub workspace_domain: Option<String>,
    #[serde(default)]
    pub ou_mapping: Option<OuMappingConfig>,
}

/// ChromeOS device sync configuration.
///
/// Separate from [`GoogleSyncConfig`], which provisions *users*. Device sync
/// is read-only against Google: it lists ChromeOS devices, OUs and users, and
/// writes only to Chalk's own tables. Credentials fall back to
/// `[google_sync]` when they are not set here, so a district that already
/// configured user provisioning turns devices on with one line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Whether Chalk may write to Google, as opposed to only reading.
    ///
    /// Separate from `enabled`, and off by default, because reading a
    /// district's fleet and changing it are different levels of trust. It also
    /// selects the scope set: domain-wide delegation matches the literal scope
    /// string, so a tenant granted the read-only scope that then requests
    /// read/write gets a 403 that looks nothing like a scope problem.
    #[serde(default)]
    pub write_back_enabled: bool,
    /// Directory API customer. `"my_customer"` resolves to the impersonated
    /// admin's own domain and is right for every self-hosted install; it was
    /// previously hardcoded in the CLI.
    #[serde(default = "default_device_customer_id")]
    pub customer_id: String,
    /// `maxResults` per `chromeosdevices.list` page. Google documents a
    /// maximum of 300; the default is 200 because a `projection=FULL` page is
    /// large and 200 has years of field evidence at district scale.
    #[serde(default = "default_device_page_size")]
    pub page_size: u32,
    #[serde(default = "default_device_sync_schedule")]
    pub sync_schedule: String,
    /// Client-side request ceiling. Sized well under Google's quota because a
    /// district's other tooling shares the same per-account limit.
    #[serde(default = "default_device_requests_per_minute")]
    pub requests_per_minute: u32,
    /// Service-account JSON key. Falls back to
    /// `google_sync.service_account_key_path`.
    #[serde(default)]
    pub service_account_key_path: Option<String>,
    /// Admin to impersonate. Falls back to `google_sync.admin_email`.
    #[serde(default)]
    pub admin_email: Option<String>,
    /// Ingest only devices at or below this OU path. Applied **locally** to
    /// the single root listing — device sync never fans out per OU, because
    /// `google_device_sync_cursors` holds one page token per resource and
    /// cannot represent N concurrent cursors.
    #[serde(default)]
    pub org_unit_filter: Option<String>,
    /// Workspace domain used to decide whether a `recentUsers` sign-in is a
    /// district account. Falls back to `google_sync.workspace_domain`.
    #[serde(default)]
    pub workspace_domain: Option<String>,
}

impl Default for DeviceSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            write_back_enabled: false,
            customer_id: default_device_customer_id(),
            page_size: default_device_page_size(),
            sync_schedule: default_device_sync_schedule(),
            requests_per_minute: default_device_requests_per_minute(),
            service_account_key_path: None,
            admin_email: None,
            org_unit_filter: None,
            workspace_domain: None,
        }
    }
}

impl DeviceSyncConfig {
    /// The service-account key to use, falling back to `[google_sync]`.
    pub fn resolved_key_path<'a>(&'a self, google_sync: &'a GoogleSyncConfig) -> Option<&'a str> {
        self.service_account_key_path
            .as_deref()
            .or(google_sync.service_account_key_path.as_deref())
    }

    /// The admin to impersonate, falling back to `[google_sync]`.
    pub fn resolved_admin_email<'a>(
        &'a self,
        google_sync: &'a GoogleSyncConfig,
    ) -> Option<&'a str> {
        self.admin_email
            .as_deref()
            .or(google_sync.admin_email.as_deref())
    }

    /// The Workspace domain, falling back to `[google_sync]`.
    pub fn resolved_workspace_domain<'a>(
        &'a self,
        google_sync: &'a GoogleSyncConfig,
    ) -> Option<&'a str> {
        self.workspace_domain
            .as_deref()
            .or(google_sync.workspace_domain.as_deref())
    }
}

fn default_device_customer_id() -> String {
    "my_customer".into()
}

/// See [`DeviceSyncConfig::page_size`].
fn default_device_page_size() -> u32 {
    200
}

fn default_device_sync_schedule() -> String {
    "0 4 * * *".into()
}

fn default_device_requests_per_minute() -> u32 {
    500
}

/// Largest `maxResults` `chromeosdevices.list` documents.
const MAX_DEVICE_PAGE_SIZE: u32 = 300;

/// Organizational Unit path templates for Google Workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuMappingConfig {
    pub students: String,
    pub teachers: String,
    pub staff: String,
}

/// AI Agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Anonymous telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Helpdesk behaviour: how long a district gives itself to answer.
///
/// # Why the target is a first response, not a resolution
///
/// "How long until someone answered" is the number a district can actually
/// commit to and a technician can actually control. Time-to-resolution depends
/// on parts, vendors and the requester replying — promising it produces either
/// padded targets nobody respects or missed ones nobody can prevent.
///
/// Hours are business-agnostic on purpose: a plain wall-clock offset is
/// something an operator can predict. A working-hours calendar is the obvious
/// next request and is deliberately not guessed at here — it needs the
/// district's own term dates and holidays, which Chalk does not have.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelpdeskConfig {
    /// Hours to first response for an urgent ticket.
    #[serde(default = "urgent_hours")]
    pub urgent_response_hours: i64,
    #[serde(default = "high_hours")]
    pub high_response_hours: i64,
    #[serde(default = "normal_hours")]
    pub normal_response_hours: i64,
    #[serde(default = "low_hours")]
    pub low_response_hours: i64,
    /// Hours to *resolution* per priority — the second SLA the PRD promised
    /// alongside first response. A non-positive value means "no target", same
    /// convention as the response hours. Defaults are looser than the response
    /// windows, because answering fast and fixing fast are different promises.
    #[serde(default = "urgent_resolution_hours")]
    pub urgent_resolution_hours: i64,
    #[serde(default = "high_resolution_hours")]
    pub high_resolution_hours: i64,
    #[serde(default = "normal_resolution_hours")]
    pub normal_resolution_hours: i64,
    #[serde(default = "low_resolution_hours")]
    pub low_resolution_hours: i64,
    /// Where inbound mail comes from, when it does.
    #[serde(default)]
    pub inbound: InboundEmailConfig,
    /// Attach the requester's assigned device to a new ticket automatically.
    ///
    /// **This is the helpdesk half of the wedge.** The device module already
    /// knows who holds what, so a teacher raising "my Chromebook will not
    /// charge" never types an asset tag and a technician never asks for one.
    /// Off is available for districts whose assignments they do not trust yet.
    #[serde(default = "enabled")]
    pub attach_requester_device: bool,
}

fn urgent_hours() -> i64 {
    2
}
fn high_hours() -> i64 {
    8
}
fn normal_hours() -> i64 {
    24
}
fn low_hours() -> i64 {
    72
}
fn urgent_resolution_hours() -> i64 {
    8
}
fn high_resolution_hours() -> i64 {
    24
}
fn normal_resolution_hours() -> i64 {
    72
}
fn low_resolution_hours() -> i64 {
    168
}

impl Default for HelpdeskConfig {
    fn default() -> Self {
        Self {
            urgent_response_hours: urgent_hours(),
            high_response_hours: high_hours(),
            normal_response_hours: normal_hours(),
            low_response_hours: low_hours(),
            urgent_resolution_hours: urgent_resolution_hours(),
            high_resolution_hours: high_resolution_hours(),
            normal_resolution_hours: normal_resolution_hours(),
            low_resolution_hours: low_resolution_hours(),
            attach_requester_device: true,
            inbound: InboundEmailConfig::default(),
        }
    }
}

/// Accepting tickets by email.
///
/// Off until a provider *and* a secret are both set, because the endpoint is
/// unauthenticated by nature — a mail provider cannot present a session — and
/// an open one would let anybody on the internet file tickets in a district's
/// queue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InboundEmailConfig {
    /// `postmark` for the hosted provider, `generic` for any relay that can
    /// POST Chalk's documented JSON. See
    /// `chalk_core::inbound_email::providers`.
    #[serde(default)]
    pub provider: Option<String>,
    /// Shared secret the provider must present, as `?secret=` or an
    /// `X-Chalk-Inbound-Secret` header.
    ///
    /// Postmark's inbound webhook URL is configured once in their dashboard,
    /// so a secret in the URL is the mechanism they support and is what this
    /// is for. Compared in constant time.
    #[serde(default)]
    pub secret: Option<String>,
}

impl InboundEmailConfig {
    /// Both halves present, or the endpoint stays closed.
    pub fn enabled(&self) -> bool {
        self.provider
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty())
            && self.secret.as_deref().is_some_and(|s| !s.trim().is_empty())
    }
}

impl ChalkSection {
    /// The base a link in an **email** must be built from.
    ///
    /// `None` when `public_url` is unset, because a link with no scheme and no
    /// host is not a link — a mail client cannot open `/help/verify?token=…`,
    /// and sending one produces a message that looks fine and does nothing.
    /// Callers must treat the absence as "cannot send" rather than joining
    /// onto an empty string.
    pub fn absolute_url_base(&self) -> Option<&str> {
        self.public_url
            .as_deref()
            .map(str::trim)
            .map(|u| u.trim_end_matches('/'))
            .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
    }
}

impl HelpdeskConfig {
    /// Hours allowed to first response at this priority.
    ///
    /// A non-positive value means "no target": a district that does not want
    /// to be measured on one priority should not be given a deadline that is
    /// already past.
    pub fn response_hours(&self, priority: crate::models::ticket::TicketPriority) -> Option<i64> {
        use crate::models::ticket::TicketPriority::*;
        let h = match priority {
            Urgent => self.urgent_response_hours,
            High => self.high_response_hours,
            Normal => self.normal_response_hours,
            Low => self.low_response_hours,
        };
        (h > 0).then_some(h)
    }

    /// Hours allowed to resolution at this priority, same "non-positive means no
    /// target" convention as [`Self::response_hours`].
    pub fn resolution_hours(&self, priority: crate::models::ticket::TicketPriority) -> Option<i64> {
        use crate::models::ticket::TicketPriority::*;
        let h = match priority {
            Urgent => self.urgent_resolution_hours,
            High => self.high_resolution_hours,
            Normal => self.normal_resolution_hours,
            Low => self.low_resolution_hours,
        };
        (h > 0).then_some(h)
    }
}

/// Marketplace integration configuration.
///
/// **Only the hosted runtime serves the marketplace.** The pages live in the
/// private hosted crate, which merges its own `/marketplace` router on top of
/// the console's; this repository has no such route and never has. The flag
/// exists so the console's sidebar can offer the link on the deployment that
/// actually answers it — turning it on in a self-hosted `chalk.toml` puts a
/// link in the sidebar that leads to a 404 and does nothing else.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MarketplaceConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Active Directory sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_sync_schedule")]
    pub sync_schedule: String,
    #[serde(default)]
    pub connection: AdConnectionConfig,
    #[serde(default)]
    pub ou_mapping: Option<AdOuMappingConfig>,
    #[serde(default)]
    pub groups: Option<AdGroupConfig>,
    #[serde(default)]
    pub passwords: Option<AdPasswordConfig>,
    #[serde(default)]
    pub options: AdSyncOptions,
}

/// AD LDAP connection settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdConnectionConfig {
    /// LDAP server URI (e.g., `ldaps://dc01.example.com:636`).
    #[serde(default)]
    pub server: String,
    /// Distinguished name used to bind (e.g., `CN=chalk-svc,OU=Service Accounts,DC=example,DC=com`).
    #[serde(default)]
    pub bind_dn: String,
    /// Password for the bind DN.
    #[serde(default)]
    pub bind_password: String,
    /// Base DN for all operations (e.g., `DC=example,DC=com`).
    #[serde(default)]
    pub base_dn: String,
    /// Whether to verify the TLS certificate.
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    /// Optional path to a CA certificate for TLS verification.
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
    /// Optional LDAP search filter applied when enumerating users.
    #[serde(default)]
    pub user_filter: Option<String>,
}

fn default_tls_verify() -> bool {
    true
}

/// OU mapping templates for AD user placement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdOuMappingConfig {
    pub students: String,
    pub teachers: String,
    pub staff: String,
}

/// AD group configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroupConfig {
    /// Whether to manage group memberships.
    #[serde(default)]
    pub enabled: bool,
    /// Base OU for groups.
    #[serde(default)]
    pub base_ou: Option<String>,
}

/// AD password generation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdPasswordConfig {
    /// Password template pattern (e.g., `"{lastName}{birthYear}!"`).
    pub pattern: String,
    /// Minimum password length.
    #[serde(default = "default_min_password_length")]
    pub min_length: usize,
}

fn default_min_password_length() -> usize {
    12
}

/// AD sync behavior options.
/// Directory schema flavor. Defaults to Active Directory; switch to
/// `OpenLdap` for stock OpenLDAP servers (the integration test target,
/// or a self-hosted directory using the standard `inetOrgPerson` schema).
///
/// Why this exists: AD's user schema is Microsoft-specific
/// (`objectClass=user`, `sAMAccountName`, `userAccountControl`,
/// `unicodePwd`). None of those exist in the stock OpenLDAP schema, so
/// adds against an OpenLDAP server return `rc=21 invalidAttributeSyntax`
/// without this flag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdSchemaFlavor {
    #[default]
    ActiveDirectory,
    OpenLdap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdSyncOptions {
    /// Whether to create new AD accounts for roster users.
    #[serde(default = "default_true")]
    pub provision_users: bool,
    /// Action for users no longer in the roster: "disable", "move_to_ou", or "delete".
    #[serde(default = "default_deprovision_action")]
    pub deprovision_action: String,
    /// Target OU when deprovision_action is "move_to_ou".
    #[serde(default)]
    pub deprovision_ou: Option<String>,
    /// Whether to create/manage OUs automatically.
    #[serde(default)]
    pub manage_ous: bool,
    /// Whether to manage group memberships.
    #[serde(default)]
    pub manage_groups: bool,
    /// Whether to sync/set passwords.
    #[serde(default)]
    pub sync_passwords: bool,
    /// Preview mode — log changes without applying.
    #[serde(default)]
    pub dry_run: bool,
    /// Directory schema flavor. Set to `open_ldap` when targeting a stock
    /// OpenLDAP server (e.g. for testing or a self-hosted directory).
    /// Defaults to `active_directory` for backwards compatibility.
    #[serde(default)]
    pub schema: AdSchemaFlavor,
}

impl Default for AdSyncOptions {
    fn default() -> Self {
        Self {
            provision_users: true,
            deprovision_action: default_deprovision_action(),
            deprovision_ou: None,
            manage_ous: false,
            manage_groups: false,
            sync_passwords: false,
            dry_run: false,
            schema: AdSchemaFlavor::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_deprovision_action() -> String {
    "disable".into()
}

/// Configuration for an SSO partner defined in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoPartnerConfig {
    pub name: String,
    pub protocol: String,
    #[serde(default)]
    pub saml_entity_id: Option<String>,
    #[serde(default)]
    pub saml_acs_url: Option<String>,
    #[serde(default)]
    pub oidc_client_id: Option<String>,
    #[serde(default)]
    pub oidc_client_secret: Option<String>,
    #[serde(default)]
    pub oidc_redirect_uris: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default = "default_sso_enabled")]
    pub enabled: bool,
    /// Filter which user types this partner serves (e.g., `["student", "teacher"]`).
    /// Empty means all user types.
    #[serde(default)]
    pub user_types: Vec<String>,
}

fn default_sso_enabled() -> bool {
    true
}

/// Configuration for a webhook endpoint defined in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    pub secret: String,
    #[serde(default = "default_webhook_security")]
    pub security: WebhookSecurityMode,
    #[serde(default = "default_webhook_mode")]
    pub mode: WebhookMode,
    #[serde(default = "default_webhook_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub entity_types: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub excluded_fields: Vec<String>,
    #[serde(default)]
    pub org_sourced_ids: Vec<String>,
}

fn default_webhook_security() -> WebhookSecurityMode {
    WebhookSecurityMode::SignOnly
}

fn default_webhook_mode() -> WebhookMode {
    WebhookMode::Batched
}

fn default_webhook_enabled() -> bool {
    true
}

impl ChalkSection {
    /// Returns true if cookies should be marked `Secure`, i.e. the
    /// configured `public_url` is HTTPS. Returns `false` for plain HTTP
    /// or when `public_url` is unset (typical for local/LAN dev).
    pub fn cookies_secure(&self) -> bool {
        self.public_url
            .as_deref()
            .map(|u| u.starts_with("https://"))
            .unwrap_or(false)
    }
}

impl ChalkConfig {
    /// Load configuration from a TOML file at the given path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| ChalkError::Config(format!("failed to parse config: {e}")))?;
        Ok(config)
    }

    /// Validate the configuration, returning an error for invalid combinations.
    pub fn validate(&self) -> Result<()> {
        if self.chalk.instance_name.is_empty() {
            return Err(ChalkError::Config(
                "chalk.instance_name must not be empty".into(),
            ));
        }

        if self.chalk.data_dir.is_empty() {
            return Err(ChalkError::Config(
                "chalk.data_dir must not be empty".into(),
            ));
        }

        // Database validation
        match self.chalk.database.driver {
            DatabaseDriver::Sqlite => {
                if self.chalk.database.path.is_none() {
                    return Err(ChalkError::Config(
                        "chalk.database.path is required when driver is sqlite".into(),
                    ));
                }
            }
            DatabaseDriver::Postgres => {
                if self.chalk.database.url.is_none() {
                    return Err(ChalkError::Config(
                        "chalk.database.url is required when driver is postgres".into(),
                    ));
                }
                match self.chalk.database.schema.as_deref() {
                    None => {
                        return Err(ChalkError::Config(
                            "chalk.database.schema is required when driver is postgres".into(),
                        ));
                    }
                    Some(s) => {
                        if !is_valid_pg_schema(s) {
                            return Err(ChalkError::Config(format!(
                                "chalk.database.schema '{s}' is invalid; must match ^[a-z][a-z0-9_]{{2,40}}$"
                            )));
                        }
                    }
                }
            }
        }

        // SIS validation. base_url is required for the network connectors;
        // the CSV connector uses csv_dir instead and has no remote endpoint.
        // When `sis.enabled = true` but `provider = None`, validation passes
        // here — the runtime emits a `tracing::warn!` at startup and the
        // sync/scheduler entry points refuse to run without a provider.
        if let Some(ref provider) = self.sis.provider {
            if self.sis.enabled
                && matches!(
                    provider,
                    SisProvider::PowerSchool | SisProvider::InfiniteCampus | SisProvider::Skyward
                )
                && self.sis.base_url.is_empty()
            {
                return Err(ChalkError::Config(
                    "sis.base_url is required when SIS is enabled".into(),
                ));
            }

            if self.sis.enabled
                && *provider == SisProvider::OneRosterCsv
                && self
                    .sis
                    .csv_dir
                    .as_ref()
                    .map(|s| s.is_empty())
                    .unwrap_or(true)
            {
                return Err(ChalkError::Config(
                    "sis.csv_dir is required when sis.provider = \"oneroster_csv\"".into(),
                ));
            }

            // token_url is required for IC and Skyward (not derivable from base_url)
            if self.sis.enabled
                && matches!(provider, SisProvider::InfiniteCampus | SisProvider::Skyward)
                && self.sis.token_url.is_none()
            {
                return Err(ChalkError::Config(format!(
                    "sis.token_url is required for {provider:?} provider"
                )));
            }
        }

        // IDP validation.
        //
        // Skipped when the roster/SSO module is off, because the module is the
        // outer gate: `serve` will not mount the IdP at all, so demanding a
        // SAML certificate would refuse startup over configuration for
        // something that can never run. Turning a module off has to be a way
        // out of a misconfiguration, not a new one.
        if self.modules.roster_sso && self.idp.enabled {
            if self.idp.saml_cert_path.is_none() {
                return Err(ChalkError::Config(
                    "idp.saml_cert_path is required when IDP is enabled".into(),
                ));
            }
            if self.idp.saml_key_path.is_none() {
                return Err(ChalkError::Config(
                    "idp.saml_key_path is required when IDP is enabled".into(),
                ));
            }
            if self.chalk.public_url.is_none() {
                return Err(ChalkError::Config(
                    "chalk.public_url is required when IDP is enabled".into(),
                ));
            }
        }

        // Google Sync validation
        if self.google_sync.enabled {
            if self.google_sync.service_account_key_path.is_none() {
                return Err(ChalkError::Config(
                    "google_sync.service_account_key_path is required when Google Sync is enabled"
                        .into(),
                ));
            }
            if self.google_sync.admin_email.is_none() {
                return Err(ChalkError::Config(
                    "google_sync.admin_email is required when Google Sync is enabled".into(),
                ));
            }
            if self.google_sync.workspace_domain.is_none() {
                return Err(ChalkError::Config(
                    "google_sync.workspace_domain is required when Google Sync is enabled".into(),
                ));
            }
            if let Some(ref key_path) = self.google_sync.service_account_key_path {
                if !Path::new(key_path).exists() {
                    return Err(ChalkError::Config(format!(
                        "google_sync.service_account_key_path file does not exist: {key_path}"
                    )));
                }
            }
        }

        // Device Sync validation. Credentials may come from [google_sync], so
        // the checks are against the resolved values, not the raw fields.
        //
        // Credentials are deliberately NOT required here. Since the console can
        // store a sealed service-account key in the database, a TOML path is
        // one of two sources rather than the only one — and refusing to start a
        // server because the *file* is absent would make the console's own
        // setup screen unreachable, which is the screen an operator would use
        // to fix it. A run with no credential from either source fails at run
        // time, where the error can name what is actually missing.
        //
        // A path that is *set but wrong* is still a hard error: that is a typo,
        // not a deployment choice.
        if self.device_sync.enabled {
            let key_path = self.device_sync.resolved_key_path(&self.google_sync);
            if let Some(path) = key_path {
                if !Path::new(path).exists() {
                    return Err(ChalkError::Config(format!(
                        "device_sync.service_account_key_path file does not exist: {path}"
                    )));
                }
            }
            if self.device_sync.page_size == 0 || self.device_sync.page_size > MAX_DEVICE_PAGE_SIZE
            {
                return Err(ChalkError::Config(format!(
                    "device_sync.page_size must be between 1 and {MAX_DEVICE_PAGE_SIZE}"
                )));
            }
            if self.device_sync.requests_per_minute == 0 {
                return Err(ChalkError::Config(
                    "device_sync.requests_per_minute must be greater than zero".into(),
                ));
            }
            if self.device_sync.customer_id.trim().is_empty() {
                return Err(ChalkError::Config(
                    "device_sync.customer_id must not be empty".into(),
                ));
            }
            if let Some(filter) = &self.device_sync.org_unit_filter {
                if !filter.starts_with('/') {
                    return Err(ChalkError::Config(format!(
                        "device_sync.org_unit_filter must be an absolute OU path starting with \
                         '/': {filter}"
                    )));
                }
            }
        }

        // AD Sync validation
        if self.ad_sync.enabled {
            if self.ad_sync.connection.server.is_empty() {
                return Err(ChalkError::Config(
                    "ad_sync.connection.server is required when AD Sync is enabled".into(),
                ));
            }
            if self.ad_sync.connection.bind_dn.is_empty() {
                return Err(ChalkError::Config(
                    "ad_sync.connection.bind_dn is required when AD Sync is enabled".into(),
                ));
            }
            if self.ad_sync.connection.base_dn.is_empty() {
                return Err(ChalkError::Config(
                    "ad_sync.connection.base_dn is required when AD Sync is enabled".into(),
                ));
            }
        }

        Ok(())
    }

    /// Generate a sensible default configuration.
    pub fn generate_default() -> Self {
        Self {
            chalk: ChalkSection {
                instance_name: "My School District".into(),
                data_dir: default_data_dir(),
                public_url: None,
                database: DatabaseConfig::default(),
                telemetry: TelemetryConfig::default(),
                admin_password_hash: None,
                alerts_email: None,
                daily_digest: false,
            },
            modules: ModulesConfig::default(),
            sis: SisConfig::default(),
            idp: IdpConfig::default(),
            google_sync: GoogleSyncConfig::default(),
            device_sync: DeviceSyncConfig::default(),
            ad_sync: AdSyncConfig::default(),
            mdm: MdmConfig::default(),
            entra: EntraConfig::default(),
            agent: AgentConfig::default(),
            marketplace: MarketplaceConfig::default(),
            helpdesk: HelpdeskConfig::default(),
            mail: None,
            sso_partners: Vec::new(),
            webhooks: Vec::new(),
        }
    }
}

/// Platform-appropriate default for the `chalk` data directory.
///
/// - **Windows**: `%LOCALAPPDATA%\chalk` (typically
///   `C:\Users\<user>\AppData\Local\chalk`). Falls back to
///   `%USERPROFILE%\chalk` then `C:\ProgramData\chalk` if `LOCALAPPDATA`
///   is unset (rare — happens in old shells or some service contexts).
/// - **macOS**: `$HOME/Library/Application Support/chalk` per Apple's
///   app-data conventions; falls back to `/var/lib/chalk` if `HOME`
///   is unset (e.g. running as a launchd system daemon).
/// - **Linux / other Unix**: `/var/lib/chalk` — the historical default,
///   correct for system installs running under a dedicated user.
///
/// Reported by a Windows user whose `chalk init` printed paths under
/// `/var/lib/chalk/…` while files were actually being created on the
/// C: drive — the printed values never matched the filesystem.
pub fn default_data_dir() -> String {
    match std::env::consts::OS {
        "windows" => std::env::var("LOCALAPPDATA")
            .ok()
            .or_else(|| std::env::var("USERPROFILE").ok())
            .map(|base| format!("{base}\\chalk"))
            .unwrap_or_else(|| "C:\\ProgramData\\chalk".to_string()),
        "macos" => std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/Library/Application Support/chalk"))
            .unwrap_or_else(|| "/var/lib/chalk".to_string()),
        _ => "/var/lib/chalk".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SAMPLE_TOML: &str = r#"
[chalk]
instance_name = "Springfield USD"
data_dir = "/var/lib/chalk"
public_url = "https://chalk.springfield.k12.us"

[chalk.database]
driver = "sqlite"
path = "/var/lib/chalk/chalk.db"

[chalk.telemetry]
enabled = false

[sis]
enabled = true
provider = "powerschool"
base_url = "https://powerschool.springfield.k12.us"
client_id = "abc"
client_secret = "secret"
sync_schedule = "0 2 * * *"

[idp]
enabled = true
qr_badge_login = true
picture_passwords = true
saml_cert_path = "/var/lib/chalk/saml.crt"
saml_key_path = "/var/lib/chalk/saml.key"
session_timeout_minutes = 480

[idp.google]
workspace_domain = "springfield.k12.us"
google_acs_url = "https://accounts.google.com/samlrp/acs"
google_entity_id = "google.com"

[google_sync]
enabled = true
provision_users = true
manage_ous = true
suspend_inactive = true
sync_schedule = "0 3 * * *"
service_account_key_path = "/var/lib/chalk/google-sa.json"
admin_email = "admin@springfield.k12.us"
workspace_domain = "springfield.k12.us"

[google_sync.ou_mapping]
students = "/Students/{school}/{grade}"
teachers = "/Teachers/{school}"
staff = "/Staff/{school}"

[agent]
enabled = false

[marketplace]
enabled = false
"#;

    fn parse_sample() -> ChalkConfig {
        toml::from_str(SAMPLE_TOML).expect("sample TOML should parse")
    }

    #[test]
    fn parse_full_config() {
        let cfg = parse_sample();
        assert_eq!(cfg.chalk.instance_name, "Springfield USD");
        assert_eq!(cfg.chalk.data_dir, "/var/lib/chalk");
        assert_eq!(
            cfg.chalk.public_url.as_deref(),
            Some("https://chalk.springfield.k12.us")
        );
        assert_eq!(cfg.chalk.database.driver, DatabaseDriver::Sqlite);
        assert_eq!(
            cfg.chalk.database.path.as_deref(),
            Some("/var/lib/chalk/chalk.db")
        );
        assert!(cfg.sis.enabled);
        assert_eq!(cfg.sis.provider, Some(SisProvider::PowerSchool));
        assert!(cfg.idp.enabled);
        assert!(cfg.idp.qr_badge_login);
        assert!(cfg.idp.picture_passwords);
        assert_eq!(
            cfg.idp.saml_cert_path.as_deref(),
            Some("/var/lib/chalk/saml.crt")
        );
        assert_eq!(
            cfg.idp.saml_key_path.as_deref(),
            Some("/var/lib/chalk/saml.key")
        );
        assert_eq!(cfg.idp.session_timeout_minutes, 480);
        let google = cfg.idp.google.as_ref().unwrap();
        assert_eq!(google.workspace_domain, "springfield.k12.us");
        assert!(cfg.google_sync.enabled);
        assert!(cfg.google_sync.provision_users);
        assert!(cfg.google_sync.manage_ous);
        assert!(cfg.google_sync.suspend_inactive);
        assert_eq!(
            cfg.google_sync.service_account_key_path.as_deref(),
            Some("/var/lib/chalk/google-sa.json")
        );
        assert_eq!(
            cfg.google_sync.admin_email.as_deref(),
            Some("admin@springfield.k12.us")
        );
        assert_eq!(
            cfg.google_sync.workspace_domain.as_deref(),
            Some("springfield.k12.us")
        );
        let ou = cfg.google_sync.ou_mapping.as_ref().unwrap();
        assert_eq!(ou.students, "/Students/{school}/{grade}");
        assert!(!cfg.agent.enabled);
        assert!(!cfg.marketplace.enabled);
        assert!(!cfg.chalk.telemetry.enabled);
    }

    #[test]
    fn roundtrip_serialization() {
        let cfg = parse_sample();
        let serialized = toml::to_string(&cfg).expect("should serialize");
        let deserialized: ChalkConfig =
            toml::from_str(&serialized).expect("should deserialize roundtrip");
        assert_eq!(deserialized.chalk.instance_name, cfg.chalk.instance_name);
        assert_eq!(deserialized.sis.provider, cfg.sis.provider);
        assert_eq!(
            deserialized.chalk.database.driver,
            cfg.chalk.database.driver
        );
    }

    #[test]
    fn generate_default_is_valid() {
        let cfg = ChalkConfig::generate_default();
        cfg.validate().expect("default config should be valid");
    }

    #[test]
    fn validate_requires_instance_name() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.instance_name = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("instance_name"));
    }

    #[test]
    fn validate_requires_data_dir() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.data_dir = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("data_dir"));
    }

    #[test]
    fn validate_requires_sqlite_path() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.database.driver = DatabaseDriver::Sqlite;
        cfg.chalk.database.path = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("path"));
    }

    #[test]
    fn validate_requires_postgres_url() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.database.driver = DatabaseDriver::Postgres;
        cfg.chalk.database.url = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("url"));
    }

    #[test]
    fn validate_postgres_with_url_passes() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.database.driver = DatabaseDriver::Postgres;
        cfg.chalk.database.path = None;
        cfg.chalk.database.url = Some("postgres://localhost/chalk".into());
        cfg.chalk.database.schema = Some("public_chalk".into());
        cfg.validate().expect("postgres with url should be valid");
    }

    #[test]
    fn validate_postgres_requires_schema() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.database.driver = DatabaseDriver::Postgres;
        cfg.chalk.database.url = Some("postgres://localhost/chalk".into());
        cfg.chalk.database.schema = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("schema"));
    }

    #[test]
    fn validate_postgres_rejects_bad_schema() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.database.driver = DatabaseDriver::Postgres;
        cfg.chalk.database.url = Some("postgres://localhost/chalk".into());
        cfg.chalk.database.schema = Some("Bad-Schema".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("schema"));
    }

    #[test]
    fn pg_schema_validator() {
        assert!(is_valid_pg_schema("tenant_a"));
        assert!(is_valid_pg_schema("abc"));
        assert!(is_valid_pg_schema("a_long_schema_with_underscores_123"));
        assert!(!is_valid_pg_schema("ab"));
        assert!(!is_valid_pg_schema("9starts_with_digit"));
        assert!(!is_valid_pg_schema("Has-Hyphen"));
        assert!(!is_valid_pg_schema("UPPER"));
        assert!(!is_valid_pg_schema(""));
    }

    #[test]
    fn validate_sis_requires_base_url_when_enabled() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        // After the 1.4 breaking change `provider` is `None` by default;
        // base_url is only required when a network provider is actually
        // chosen, so pin one here to exercise the validator branch.
        cfg.sis.provider = Some(SisProvider::PowerSchool);
        cfg.sis.base_url = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn validate_sis_disabled_no_base_url_ok() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = false;
        cfg.sis.base_url = String::new();
        cfg.validate()
            .expect("disabled SIS should not require base_url");
    }

    #[test]
    fn validate_ic_requires_token_url() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.provider = Some(SisProvider::InfiniteCampus);
        cfg.sis.base_url = "https://ic.example.com".into();
        cfg.sis.token_url = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("token_url"));
    }

    #[test]
    fn validate_skyward_requires_token_url() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.provider = Some(SisProvider::Skyward);
        cfg.sis.base_url = "https://skyward.example.com".into();
        cfg.sis.token_url = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("token_url"));
    }

    #[test]
    fn validate_ic_with_token_url_passes() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.provider = Some(SisProvider::InfiniteCampus);
        cfg.sis.base_url = "https://ic.example.com".into();
        cfg.sis.token_url = Some("https://ic.example.com/oauth/token".into());
        cfg.validate().expect("IC with token_url should be valid");
    }

    #[test]
    fn validate_powerschool_no_token_url_ok() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.enabled = true;
        cfg.sis.provider = Some(SisProvider::PowerSchool);
        cfg.sis.base_url = "https://ps.example.com".into();
        cfg.sis.token_url = None;
        cfg.validate()
            .expect("PowerSchool should not require token_url");
    }

    /// `wire_name` and `from_wire_name` must round-trip exhaustively and agree
    /// with the `#[serde(rename = …)]` strings on the enum variants. If a new
    /// variant is added without updating the helpers, this test catches it.
    #[test]
    fn sis_provider_wire_name_round_trip() {
        for v in [
            SisProvider::PowerSchool,
            SisProvider::InfiniteCampus,
            SisProvider::Skyward,
            SisProvider::OneRosterCsv,
        ] {
            let name = v.wire_name();
            assert_eq!(SisProvider::from_wire_name(name), Some(v.clone()));
            // serde rename emits the same string.
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(json, format!("\"{name}\""));
        }
        assert_eq!(SisProvider::from_wire_name("nope"), None);
    }

    /// Validates that an existing TOML file with `provider = "powerschool"`
    /// continues to deserialize as `Some(SisProvider::PowerSchool)` after the
    /// breaking change. Locks the serde wire format.
    #[test]
    fn sis_provider_string_deserializes_as_some() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[sis]
provider = "powerschool"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.sis.provider, Some(SisProvider::PowerSchool));
    }

    /// An empty `[sis]` section (or one that omits the `provider` key)
    /// deserializes as `None` — the new default. This is the post-1.4 wire
    /// contract; documented in CHANGELOG as a breaking change.
    #[test]
    fn sis_section_without_provider_is_none() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[sis]
enabled = false
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).expect("parse");
        assert!(cfg.sis.provider.is_none());
    }

    #[test]
    fn token_url_roundtrip_serialization() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.sis.token_url = Some("https://example.com/oauth/token".into());
        let serialized = toml::to_string(&cfg).expect("should serialize");
        let deserialized: ChalkConfig =
            toml::from_str(&serialized).expect("should deserialize roundtrip");
        assert_eq!(
            deserialized.sis.token_url.as_deref(),
            Some("https://example.com/oauth/token")
        );
    }

    #[test]
    fn sis_provider_serialization() {
        assert_eq!(
            serde_json::to_string(&SisProvider::PowerSchool).unwrap(),
            "\"powerschool\""
        );
        assert_eq!(
            serde_json::to_string(&SisProvider::InfiniteCampus).unwrap(),
            "\"infinite_campus\""
        );
        assert_eq!(
            serde_json::to_string(&SisProvider::Skyward).unwrap(),
            "\"skyward\""
        );
    }

    #[test]
    fn database_driver_serialization() {
        assert_eq!(
            serde_json::to_string(&DatabaseDriver::Sqlite).unwrap(),
            "\"sqlite\""
        );
        assert_eq!(
            serde_json::to_string(&DatabaseDriver::Postgres).unwrap(),
            "\"postgres\""
        );
    }

    #[test]
    fn load_from_file() {
        let dir = std::env::temp_dir().join("chalk_test_config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chalk.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(SAMPLE_TOML.as_bytes()).unwrap();

        let cfg = ChalkConfig::load(&path).expect("should load from file");
        assert_eq!(cfg.chalk.instance_name, "Springfield USD");

        // cleanup
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn load_nonexistent_file_returns_io_error() {
        let result = ChalkConfig::load(Path::new("/nonexistent/chalk.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn load_invalid_toml_returns_config_error() {
        let dir = std::env::temp_dir().join("chalk_test_bad_toml");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "this is [[[not valid toml").unwrap();

        let result = ChalkConfig::load(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("config"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn minimal_config_parses() {
        let minimal = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp/chalk"
"#;
        let cfg: ChalkConfig = toml::from_str(minimal).expect("minimal config should parse");
        assert_eq!(cfg.chalk.instance_name, "Test");
        assert!(!cfg.sis.enabled);
        assert!(!cfg.idp.enabled);
    }

    #[test]
    fn all_sis_providers_deserialize() {
        for (s, expected) in [
            ("\"powerschool\"", SisProvider::PowerSchool),
            ("\"infinite_campus\"", SisProvider::InfiniteCampus),
            ("\"skyward\"", SisProvider::Skyward),
        ] {
            let parsed: SisProvider = serde_json::from_str(s).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn both_db_drivers_deserialize() {
        for (s, expected) in [
            ("\"sqlite\"", DatabaseDriver::Sqlite),
            ("\"postgres\"", DatabaseDriver::Postgres),
        ] {
            let parsed: DatabaseDriver = serde_json::from_str(s).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn validate_idp_requires_cert_path() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = true;
        cfg.idp.saml_cert_path = None;
        cfg.idp.saml_key_path = Some("/tmp/key.pem".into());
        cfg.chalk.public_url = Some("https://chalk.example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("saml_cert_path"));
    }

    #[test]
    fn validate_idp_requires_key_path() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = true;
        cfg.idp.saml_cert_path = Some("/tmp/cert.pem".into());
        cfg.idp.saml_key_path = None;
        cfg.chalk.public_url = Some("https://chalk.example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("saml_key_path"));
    }

    #[test]
    fn cookies_secure_true_for_https() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.public_url = Some("https://chalk.example.com".into());
        assert!(cfg.chalk.cookies_secure());
    }

    #[test]
    fn cookies_secure_false_for_http() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.public_url = Some("http://localhost:8080".into());
        assert!(!cfg.chalk.cookies_secure());
    }

    #[test]
    fn cookies_secure_false_when_unset() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.chalk.public_url = None;
        assert!(!cfg.chalk.cookies_secure());
    }

    #[test]
    fn validate_idp_requires_public_url() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = true;
        cfg.idp.saml_cert_path = Some("/tmp/cert.pem".into());
        cfg.idp.saml_key_path = Some("/tmp/key.pem".into());
        cfg.chalk.public_url = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("public_url"));
    }

    #[test]
    fn validate_idp_fully_configured_passes() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = true;
        cfg.idp.saml_cert_path = Some("/tmp/cert.pem".into());
        cfg.idp.saml_key_path = Some("/tmp/key.pem".into());
        cfg.chalk.public_url = Some("https://chalk.example.com".into());
        cfg.validate().expect("fully configured IDP should pass");
    }

    #[test]
    fn validate_idp_disabled_no_validation() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.idp.enabled = false;
        cfg.idp.saml_cert_path = None;
        cfg.idp.saml_key_path = None;
        cfg.validate()
            .expect("disabled IDP should not require cert/key");
    }

    #[test]
    fn validate_google_sync_requires_service_account_key() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path = None;
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = Some("example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("service_account_key_path"));
    }

    #[test]
    fn validate_google_sync_requires_admin_email() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path = Some("/tmp/sa.json".into());
        cfg.google_sync.admin_email = None;
        cfg.google_sync.workspace_domain = Some("example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("admin_email"));
    }

    #[test]
    fn validate_google_sync_requires_workspace_domain() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path = Some("/tmp/sa.json".into());
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("workspace_domain"));
    }

    #[test]
    fn validate_google_sync_fully_configured_passes() {
        let dir = std::env::temp_dir().join("chalk_test_gsync_valid");
        std::fs::create_dir_all(&dir).unwrap();
        let sa_path = dir.join("sa.json");
        std::fs::write(&sa_path, "{}").unwrap();

        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path = Some(sa_path.to_str().unwrap().to_string());
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = Some("example.com".into());
        cfg.validate()
            .expect("fully configured Google Sync should pass");

        std::fs::remove_file(&sa_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// A temp service-account key file, returned with its directory so the
    /// caller can clean both up.
    fn temp_key_file(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sa.json");
        std::fs::write(&path, "{}").unwrap();
        (dir, path)
    }

    #[test]
    fn device_sync_defaults_are_the_documented_constants() {
        let cfg = DeviceSyncConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.customer_id, "my_customer");
        assert_eq!(
            cfg.page_size, 200,
            "200, not Google's documented 300 maximum — see DeviceSyncConfig::page_size"
        );
        assert_eq!(cfg.requests_per_minute, 500);
        assert!(cfg.org_unit_filter.is_none());
    }

    #[test]
    fn disabled_device_sync_needs_no_credentials() {
        let cfg = ChalkConfig::generate_default();
        assert!(!cfg.device_sync.enabled);
        cfg.validate()
            .expect("disabled device sync should not require credentials");
    }

    #[test]
    fn device_sync_credentials_fall_back_to_google_sync() {
        let (dir, sa_path) = temp_key_file("chalk_test_devsync_fallback");

        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.service_account_key_path = Some(sa_path.to_str().unwrap().to_string());
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = Some("example.com".into());
        cfg.device_sync.enabled = true;

        cfg.validate()
            .expect("device sync should inherit google_sync credentials");
        assert_eq!(
            cfg.device_sync.resolved_admin_email(&cfg.google_sync),
            Some("admin@example.com")
        );
        assert_eq!(
            cfg.device_sync.resolved_workspace_domain(&cfg.google_sync),
            Some("example.com")
        );

        std::fs::remove_file(&sa_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn device_sync_own_credentials_win_over_google_sync() {
        let (dir, sa_path) = temp_key_file("chalk_test_devsync_override");

        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.service_account_key_path = Some("/nonexistent/other.json".into());
        cfg.google_sync.admin_email = Some("wrong@example.com".into());
        cfg.device_sync.enabled = true;
        cfg.device_sync.service_account_key_path = Some(sa_path.to_str().unwrap().to_string());
        cfg.device_sync.admin_email = Some("devices@example.com".into());

        cfg.validate()
            .expect("explicit device credentials are used");
        assert_eq!(
            cfg.device_sync.resolved_admin_email(&cfg.google_sync),
            Some("devices@example.com")
        );

        std::fs::remove_file(&sa_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// Credentials are no longer required in TOML, because the console can
    /// store a sealed key in the database instead.
    ///
    /// Requiring them here would make the console's own setup screen
    /// unreachable on a fresh install — the server would refuse to start, and
    /// the screen an operator would use to fix that is served by the server.
    /// A run with no credential from *either* source fails at run time, where
    /// the error can name what is actually missing.
    #[test]
    fn device_sync_may_be_enabled_before_credentials_exist_in_toml() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.device_sync.enabled = true;
        assert!(
            cfg.validate().is_ok(),
            "enabling device sync must not require a TOML key path — the \
             console stores one in the database"
        );

        cfg.device_sync.admin_email = Some("admin@example.com".into());
        assert!(cfg.validate().is_ok());
    }

    /// A path that is *set but wrong* is still a hard error. That is a typo,
    /// not a deployment choice, and starting anyway would defer a certain
    /// failure to 4am.
    #[test]
    fn validate_device_sync_rejects_a_key_path_that_does_not_exist() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.device_sync.enabled = true;
        cfg.device_sync.service_account_key_path =
            Some("/nonexistent/definitely-not-here.json".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn validate_device_sync_rejects_an_out_of_range_page_size() {
        let (dir, sa_path) = temp_key_file("chalk_test_devsync_page");

        let mut cfg = ChalkConfig::generate_default();
        cfg.device_sync.enabled = true;
        cfg.device_sync.service_account_key_path = Some(sa_path.to_str().unwrap().to_string());
        cfg.device_sync.admin_email = Some("admin@example.com".into());

        cfg.device_sync.page_size = 301;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("page_size"));

        cfg.device_sync.page_size = 0;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("page_size"));

        cfg.device_sync.page_size = 300;
        cfg.validate().expect("300 is the documented maximum");

        std::fs::remove_file(&sa_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn validate_device_sync_rejects_a_relative_org_unit_filter() {
        let (dir, sa_path) = temp_key_file("chalk_test_devsync_ou");

        let mut cfg = ChalkConfig::generate_default();
        cfg.device_sync.enabled = true;
        cfg.device_sync.service_account_key_path = Some(sa_path.to_str().unwrap().to_string());
        cfg.device_sync.admin_email = Some("admin@example.com".into());
        cfg.device_sync.org_unit_filter = Some("Students".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("org_unit_filter"));

        cfg.device_sync.org_unit_filter = Some("/Students".into());
        cfg.validate().expect("absolute OU paths are accepted");

        std::fs::remove_file(&sa_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn device_sync_section_parses_from_toml() {
        let toml_str = r#"
[chalk]
instance_name = "Test District"
data_dir = "/var/lib/chalk"

[device_sync]
enabled = true
page_size = 250
customer_id = "C01abcdef"
org_unit_filter = "/Students"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.device_sync.enabled);
        assert_eq!(cfg.device_sync.page_size, 250);
        assert_eq!(cfg.device_sync.customer_id, "C01abcdef");
        assert_eq!(
            cfg.device_sync.org_unit_filter.as_deref(),
            Some("/Students")
        );
        // Unset fields still take their defaults.
        assert_eq!(cfg.device_sync.requests_per_minute, 500);
    }

    #[test]
    fn validate_google_sync_key_file_must_exist() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = true;
        cfg.google_sync.service_account_key_path = Some("/nonexistent/path/sa-key.json".into());
        cfg.google_sync.admin_email = Some("admin@example.com".into());
        cfg.google_sync.workspace_domain = Some("example.com".into());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn validate_google_sync_disabled_no_validation() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.enabled = false;
        cfg.google_sync.service_account_key_path = None;
        cfg.validate()
            .expect("disabled Google Sync should not require keys");
    }

    #[test]
    fn idp_session_timeout_default() {
        let cfg = ChalkConfig::generate_default();
        assert_eq!(cfg.idp.session_timeout_minutes, 480);
    }

    #[test]
    fn idp_password_pattern_defaults() {
        let cfg = ChalkConfig::generate_default();
        assert!(cfg.idp.default_password_pattern.is_none());
        assert!(cfg.idp.default_password_roles.is_empty());
    }

    #[test]
    fn idp_password_pattern_parses() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[idp]
default_password_pattern = "{lastName}{birthYear}"
default_password_roles = ["student", "teacher"]
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            cfg.idp.default_password_pattern.as_deref(),
            Some("{lastName}{birthYear}")
        );
        assert_eq!(cfg.idp.default_password_roles, vec!["student", "teacher"]);
    }

    #[test]
    fn webhook_config_parses_from_toml() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[[webhooks]]
name = "My LMS"
url = "https://lms.example.com/webhook"
secret = "super-secret"
security = "sign_only"
mode = "batched"
enabled = true
entity_types = ["user", "enrollment"]
roles = ["student"]
excluded_fields = ["demographics.birthDate"]
org_sourced_ids = ["org-1"]

[[webhooks]]
name = "Analytics"
url = "https://analytics.example.com/hook"
secret = "analytics-key"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.webhooks.len(), 2);

        let first = &cfg.webhooks[0];
        assert_eq!(first.name, "My LMS");
        assert_eq!(first.url, "https://lms.example.com/webhook");
        assert_eq!(first.secret, "super-secret");
        assert_eq!(
            first.security,
            crate::webhooks::models::WebhookSecurityMode::SignOnly
        );
        assert_eq!(first.mode, crate::webhooks::models::WebhookMode::Batched);
        assert!(first.enabled);
        assert_eq!(first.entity_types, vec!["user", "enrollment"]);
        assert_eq!(first.roles, vec!["student"]);
        assert_eq!(first.excluded_fields, vec!["demographics.birthDate"]);
        assert_eq!(first.org_sourced_ids, vec!["org-1"]);

        let second = &cfg.webhooks[1];
        assert_eq!(second.name, "Analytics");
        assert!(second.enabled); // default
        assert_eq!(
            second.security,
            crate::webhooks::models::WebhookSecurityMode::SignOnly
        ); // default
        assert_eq!(second.mode, crate::webhooks::models::WebhookMode::Batched); // default
        assert!(second.entity_types.is_empty());
    }

    #[test]
    fn webhook_config_defaults_when_absent() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.webhooks.is_empty());
    }

    #[test]
    fn webhook_config_encrypted_mode() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[[webhooks]]
name = "Encrypted Hook"
url = "https://example.com/hook"
secret = "key"
security = "encrypted"
mode = "per_entity"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.webhooks.len(), 1);
        assert_eq!(
            cfg.webhooks[0].security,
            crate::webhooks::models::WebhookSecurityMode::Encrypted
        );
        assert_eq!(
            cfg.webhooks[0].mode,
            crate::webhooks::models::WebhookMode::PerEntity
        );
    }

    #[test]
    fn webhook_config_roundtrip_serialization() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[[webhooks]]
name = "Hook"
url = "https://example.com/hook"
secret = "key"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        let serialized = toml::to_string(&cfg).expect("should serialize");
        let deserialized: ChalkConfig =
            toml::from_str(&serialized).expect("should deserialize roundtrip");
        assert_eq!(deserialized.webhooks.len(), 1);
        assert_eq!(deserialized.webhooks[0].name, "Hook");
        assert_eq!(deserialized.webhooks[0].url, "https://example.com/hook");
    }

    #[test]
    fn sso_partners_config_parses_from_toml() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[[sso_partners]]
name = "Canvas LMS"
protocol = "saml"
saml_entity_id = "https://canvas.example.com"
saml_acs_url = "https://canvas.example.com/saml/consume"
roles = ["student", "teacher"]
logo_url = "https://canvas.example.com/logo.png"
enabled = true

[[sso_partners]]
name = "Reading App"
protocol = "oidc"
oidc_client_id = "chalk-reading-app"
oidc_client_secret = "secret123"
oidc_redirect_uris = ["https://reading.app/callback"]
roles = ["student"]
enabled = true
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.sso_partners.len(), 2);

        let canvas = &cfg.sso_partners[0];
        assert_eq!(canvas.name, "Canvas LMS");
        assert_eq!(canvas.protocol, "saml");
        assert_eq!(
            canvas.saml_entity_id.as_deref(),
            Some("https://canvas.example.com")
        );
        assert_eq!(
            canvas.saml_acs_url.as_deref(),
            Some("https://canvas.example.com/saml/consume")
        );
        assert_eq!(canvas.roles, vec!["student", "teacher"]);
        assert!(canvas.enabled);

        let reading = &cfg.sso_partners[1];
        assert_eq!(reading.name, "Reading App");
        assert_eq!(reading.protocol, "oidc");
        assert_eq!(reading.oidc_client_id.as_deref(), Some("chalk-reading-app"));
        assert_eq!(reading.oidc_client_secret.as_deref(), Some("secret123"));
        assert_eq!(
            reading.oidc_redirect_uris,
            vec!["https://reading.app/callback"]
        );
        assert_eq!(reading.roles, vec!["student"]);
    }

    #[test]
    fn sso_partners_config_defaults_when_absent() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.sso_partners.is_empty());
    }

    #[test]
    fn sso_partners_config_enabled_defaults_true() {
        let toml_str = r#"
[chalk]
instance_name = "Test"
data_dir = "/tmp"

[[sso_partners]]
name = "Test App"
protocol = "saml"
"#;
        let cfg: ChalkConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.sso_partners.len(), 1);
        assert!(cfg.sso_partners[0].enabled);
    }

    #[test]
    fn ou_mapping_roundtrip() {
        let mut cfg = ChalkConfig::generate_default();
        cfg.google_sync.ou_mapping = Some(OuMappingConfig {
            students: "/Students/{school}/{grade}".into(),
            teachers: "/Teachers/{school}".into(),
            staff: "/Staff".into(),
        });
        let serialized = toml::to_string(&cfg).expect("should serialize");
        let deserialized: ChalkConfig =
            toml::from_str(&serialized).expect("should deserialize roundtrip");
        let ou = deserialized.google_sync.ou_mapping.unwrap();
        assert_eq!(ou.students, "/Students/{school}/{grade}");
        assert_eq!(ou.teachers, "/Teachers/{school}");
        assert_eq!(ou.staff, "/Staff");
    }
}

#[cfg(test)]
mod roster_sso_module_tests {
    use super::*;

    /// Turning a module off must be a way *out* of a misconfiguration, not a
    /// new one. `serve` will not mount the IdP when the module is off, so
    /// refusing to start over a missing SAML certificate would be demanding
    /// configuration for something that can never run.
    #[test]
    fn idp_requirements_are_not_enforced_when_the_module_is_off() {
        let mut config = ChalkConfig::generate_default();
        config.idp.enabled = true;
        config.idp.saml_cert_path = None;
        config.idp.saml_key_path = None;

        config.modules.roster_sso = true;
        assert!(
            config.validate().is_err(),
            "with the module on, an enabled IdP still needs its certificate"
        );

        config.modules.roster_sso = false;
        assert!(
            config.validate().is_ok(),
            "with the module off the IdP never mounts, so it needs nothing"
        );
    }
}

/// `[mdm]` — the non-Google device consoles (WS-14).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MdmConfig {
    #[serde(default)]
    pub intune: IntuneConfig,
    #[serde(default)]
    pub jamf: JamfConfig,
}

/// `[mdm.intune]` — app-only Graph credentials, the same plaintext-in-config
/// shape the AD sync uses for its bind credentials.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntuneConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The Entra tenant id (GUID or domain).
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// Test seam: overrides both the login and Graph hosts. Never set in a
    /// real deployment.
    #[serde(default)]
    pub base_url: Option<String>,
}

impl IntuneConfig {
    pub fn is_configured(&self) -> bool {
        self.enabled
            && !self.tenant_id.trim().is_empty()
            && !self.client_id.trim().is_empty()
            && !self.client_secret.trim().is_empty()
    }
}

/// `[mdm.jamf]` — a Jamf Pro API client with the Mobile Devices read
/// privilege.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JamfConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The Jamf Pro server, e.g. `https://district.jamfcloud.com`.
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
}

impl JamfConfig {
    pub fn is_configured(&self) -> bool {
        self.enabled
            && !self.url.trim().is_empty()
            && !self.client_id.trim().is_empty()
            && !self.client_secret.trim().is_empty()
    }
}

/// `[entra]` — Entra ID (Azure AD) user provisioning (WS-15b).
///
/// App-only client credentials, like the Intune connector: the district
/// registers an app, grants `User.ReadWrite.All` as an application
/// permission, and pastes tenant id / client id / client secret here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntraConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// The UPN suffix accounts are created under, e.g. `district.org` —
    /// `maya.chen` becomes `maya.chen@district.org`.
    #[serde(default)]
    pub domain: String,
    /// Test seam: one origin standing in for both the login host and the
    /// Graph host. Absent in production.
    #[serde(default)]
    pub base_url: Option<String>,
}

impl EntraConfig {
    pub fn is_configured(&self) -> bool {
        self.enabled
            && !self.tenant_id.trim().is_empty()
            && !self.client_id.trim().is_empty()
            && !self.client_secret.trim().is_empty()
            && !self.domain.trim().is_empty()
    }
}
