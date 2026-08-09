//! Route-level authorization (GP-2): the one table that says what each route
//! demands, consulted by the auth middleware before any handler runs.
//!
//! # Why a central table and not per-handler checks
//!
//! A check inside a handler is a check someone forgets on the next handler.
//! Here every route's requirement is declared in one match, the middleware
//! enforces it uniformly, and two guards keep the table honest:
//! `scripts/route-permission-lint.sh` fails the build when a route in
//! `lib.rs` has no entry here, and the tests below drive the real router to
//! prove the declarations mean what they say. An unmapped **mutating** route
//! fails closed at runtime as the last line of defense.
//!
//! GET routes with no entry are allowed (reads were never gated per-surface
//! before GP-2, and row-level site scoping still filters what they show),
//! but the lint forces a declaration anyway so the omission is a decision,
//! not an accident.

use axum::http::Method;
use chalk_core::models::console_user::Actor;
use chalk_core::models::permission::Permission;
use chalk_core::models::site_scope::SiteScope;
use std::collections::HashSet;

/// What a route demands of the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAuthz {
    /// No session at all (login, the staff portal, tokened public forms).
    /// The middleware never consults the table for these — `is_public_path`
    /// runs first — but declaring them keeps the lint's ledger complete.
    Public,
    /// Any authenticated principal: their own account, their own exit.
    SelfService,
    /// Requires the permission; the route only reads.
    Read(Permission),
    /// Requires the permission; the route mutates.
    Write(Permission),
}

/// The requirement for one `(method, matched route template)` pair.
///
/// Templates are axum's (`/devices/:id/checkout`), taken from `MatchedPath`
/// so this never re-implements routing. `None` means "not declared" — which
/// the middleware refuses for mutating methods.
pub fn route_authz(method: &Method, matched: &str) -> Option<RouteAuthz> {
    use Permission as P;
    use RouteAuthz::{Public, Read, SelfService, Write};
    let get = *method == Method::GET || *method == Method::HEAD;
    Some(match matched {
        // -- No session: auth flows, the staff help portal, tokened public
        // surfaces, unauthenticated plumbing. `is_public_path` handles these
        // before the table is consulted.
        "/health"
        | "/static/htmx-2.0.4.min.js"
        | "/static/bricolage-grotesque.woff2"
        | "/login"
        | "/login/totp"
        | "/login/sso"
        | "/login/sso/callback"
        | "/login/verify"
        | "/set-password"
        | "/help/signin"
        | "/help/verify"
        | "/help/signout"
        | "/help"
        | "/help/new"
        | "/help/kb"
        | "/help/kb/:id"
        | "/help/:id"
        | "/help/:id/reply"
        | "/inbound/email"
        | "/csat/:token/:score"
        | "/attest/:token" => Public,

        // -- Any signed-in principal.
        "/"
        | "/logout"
        | "/account/security"
        | "/account/security/totp/start"
        | "/account/security/totp/confirm"
        | "/account/security/totp/disable" => SelfService,

        // -- Devices: looking.
        "/devices"
        | "/devices/export.csv"
        | "/devices/unmatched"
        | "/devices/history"
        | "/devices/scan"
        | "/devices/labels"
        | "/devices/labels/:id"
        | "/devices/:id" => Read(P::AssetsView),
        // The audit walk mutates nothing server-side — its state rides in the
        // form — so its POST demands only the view permission.
        "/devices/audit" if get => Read(P::AssetsView),
        "/devices/audit" => Write(P::AssetsView),

        // -- Devices: changing local records. Form GETs carry the write
        // permission too: an edit form a caller can never submit is not a
        // read, it is a dead end.
        "/devices/new" | "/devices/:id/edit" | "/devices/import" | "/devices/:id/resolve" => {
            if get {
                Read(P::AssetsEdit)
            } else {
                Write(P::AssetsEdit)
            }
        }
        "/devices/:id/ignore" | "/devices/unmatched/bulk-ignore" => Write(P::AssetsEdit),
        "/devices/:id/lost" | "/devices/:id/found" => Write(P::AssetsEdit),

        // -- Devices: connectors, sync, and the change-set pipeline out to
        // remote consoles.
        "/devices/connect" | "/devices/sync" => {
            if get {
                Read(P::AssetsSync)
            } else {
                Write(P::AssetsSync)
            }
        }
        "/devices/connect/test"
        | "/devices/changes"
        | "/devices/changes/:id/exclude"
        | "/devices/changes/:id/commit"
        | "/devices/changes/:id/discard" => Write(P::AssetsSync),
        "/devices/sync/status" | "/devices/changes/:id" => Read(P::AssetsSync),

        // -- Circulation and attestation.
        "/devices/circulation" => Read(P::CustodyView),
        "/devices/:id/checkout" | "/devices/:id/checkin" => Write(P::CustodyManage),
        "/devices/attestations" => Read(P::CustodyView),
        "/devices/attestations/start" | "/devices/attestations/resend" => Write(P::CustodyManage),

        // -- Money and repairs.
        "/devices/:id/repairs" | "/devices/:id/repairs/close" => Write(P::RepairsManage),
        "/devices/:id/charges" => Write(P::FeesAssess),
        "/charges/:id/waive" | "/charges/:id/settle" => Write(P::FeesWaive),

        // -- Quantity items.
        "/items" if get => Read(P::ItemsView),
        "/items" => Write(P::ItemsManage),
        "/items/:id" => Read(P::ItemsView),
        "/items/:id/issue"
        | "/items/:id/adjust"
        | "/items/:id/delete"
        | "/items/:id/holdings/:holding_id/return" => Write(P::ItemsManage),

        // -- Reports.
        "/devices/reports"
        | "/devices/reports/custom/:id"
        | "/devices/reports/custom/:id/export.csv" => Read(P::ReportsView),
        "/devices/reports/custom" if get => Read(P::ReportsView),
        "/devices/reports/custom" => Write(P::ReportsBuild),
        "/devices/reports/custom/:id/delete" => Write(P::ReportsBuild),

        // -- Help desk.
        "/tickets" | "/tickets/analytics" | "/tickets/:id" | "/attachments/:id" => {
            Read(P::TicketsView)
        }
        "/tickets/new" if get => Read(P::TicketsWork),
        "/tickets/new" => Write(P::TicketsWork),
        "/tickets/:id/comment"
        | "/tickets/:id/status"
        | "/tickets/:id/assign"
        | "/tickets/:id/reclassify"
        | "/tickets/:id/tags" => Write(P::TicketsWork),
        "/tickets/views" | "/tickets/views/:id/delete" => Write(P::TicketsConfigure),

        // -- Knowledge base (console side).
        "/kb" if get => Read(P::KbView),
        "/kb" => Write(P::KbEdit),
        "/kb/:id" if get => Read(P::KbView),
        "/kb/:id" | "/kb/:id/delete" => Write(P::KbEdit),

        // -- Identity surfaces.
        "/identity"
        | "/identity/sessions"
        | "/identity/badges"
        | "/identity/auth-log"
        | "/identity/saml-setup"
        | "/identity/saml-cert.pem"
        | "/users"
        | "/users/:id" => Read(P::IdentityView),
        "/identity/badges/:user_id/generate"
        | "/identity/badges/issue"
        | "/identity/badges/:id/revoke" => Write(P::IdentityBadges),
        "/sso-partners" | "/sso-partners/:id" => Read(P::IdentityView),
        "/sso-partners/new" | "/sso-partners/:id/edit" => {
            if get {
                Read(P::IdentitySso)
            } else {
                Write(P::IdentitySso)
            }
        }
        "/sso-partners/:id/toggle" => Write(P::IdentitySso),

        // -- Sync operations: dashboards are viewable with settings.view
        // (ReadOnly kept its look-at-everything contract), config and
        // triggers demand the connector permission.
        "/sync"
        | "/sync/history"
        | "/google-sync"
        | "/google-sync/history"
        | "/google-sync/users"
        | "/ad-sync"
        | "/ad-sync/history"
        | "/ad-sync/users"
        | "/migration"
        | "/migration/clever"
        | "/migration/classlink" => Read(P::SettingsView),
        "/sync/trigger"
        | "/sync/schedule"
        | "/google-sync/trigger"
        | "/google-sync/schedule"
        | "/ad-sync/trigger" => Write(P::SettingsSyncConfig),
        "/sync/settings" | "/google-sync/settings" | "/identity/settings" | "/ad-sync/settings" => {
            if get {
                Read(P::SettingsSyncConfig)
            } else {
                Write(P::SettingsSyncConfig)
            }
        }

        // -- Settings and administration.
        "/settings" => Read(P::SettingsView),
        "/settings/audit-log" => Read(P::AuditView),
        "/settings/api-tokens" => {
            if get {
                Read(P::ApiTokensManage)
            } else {
                Write(P::ApiTokensManage)
            }
        }
        "/settings/api-tokens/:id/revoke" => Write(P::ApiTokensManage),
        // GET included: the account list was admin-only before GP-2 too.
        "/settings/console-users" => {
            if get {
                Read(P::ConsoleUsersManage)
            } else {
                Write(P::ConsoleUsersManage)
            }
        }
        "/settings/console-users/:id/toggle" => Write(P::ConsoleUsersManage),
        "/settings/console-users/:id/access" | "/settings/permission-sets" => {
            if get {
                Read(P::ConsoleUsersManage)
            } else {
                Write(P::ConsoleUsersManage)
            }
        }
        "/settings/permission-sets/:id/delete" => Write(P::ConsoleUsersManage),
        "/settings/canned-responses" if get => Read(P::SettingsView),
        "/settings/canned-responses" | "/settings/canned-responses/:id/delete" => {
            Write(P::TicketsConfigure)
        }
        "/settings/routing-rules" if get => Read(P::SettingsView),
        "/settings/routing-rules" | "/settings/routing-rules/:id/delete" => {
            Write(P::TicketsConfigure)
        }
        "/webhooks" | "/webhooks/:id" => Read(P::SettingsView),
        "/webhooks/new" | "/webhooks/:id/edit" => {
            if get {
                Read(P::WebhooksManage)
            } else {
                Write(P::WebhooksManage)
            }
        }
        "/webhooks/:id/delete" | "/webhooks/:id/test" => Write(P::WebhooksManage),

        _ => return None,
    })
}

/// The resolved caller: identity plus what they may do and where.
///
/// Sits in request extensions beside [`Actor`] — `Actor` answers "who did
/// this" for audit lines, `Principal` answers "may they" for handlers that
/// need row-level scope.
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor: Actor,
    pub permissions: HashSet<Permission>,
    pub scope: SiteScope,
}

impl Principal {
    pub fn allows(&self, p: Permission) -> bool {
        self.permissions.contains(&p)
    }

    /// Apply this principal's site boundary to an asset filter, pushed into
    /// SQL so pagination and counts agree with what the caller may see.
    ///
    /// Composes with whatever the caller already filtered: their choice
    /// narrows *within* the boundary (intersection), never widens past it.
    pub fn scope_asset_filter(
        &self,
        mut f: chalk_core::models::asset::AssetFilter,
    ) -> chalk_core::models::asset::AssetFilter {
        if let Some(schools) = self.scope.schools() {
            if f.school_org_sourced_ids.is_empty() {
                f.school_org_sourced_ids = schools.to_vec();
            } else {
                f.school_org_sourced_ids
                    .retain(|s| schools.iter().any(|x| x == s));
            }
            if f.school_org_sourced_ids.is_empty() {
                // Empty after intersecting (or an empty grant): an
                // impossible id keeps the IN-list present so the boundary
                // cannot silently vanish into "unrestricted".
                f.school_org_sourced_ids = vec!["\u{0}no-school".to_string()];
            }
            f.include_unscoped_school = self.scope.includes_unscoped();
        }
        f
    }

    /// The object-level check for a loaded row: is this school (or the lack
    /// of one) inside the boundary?
    pub fn permits_school(&self, school: Option<&str>) -> bool {
        self.scope.permits(school)
    }

    /// The district itself: full permissions, no site boundary. What the
    /// shared admin password, the local-dev shortcut, and any principal
    /// without a console-user row resolve to.
    pub fn unrestricted(actor: Actor) -> Self {
        Self {
            permissions: Permission::ALL.iter().copied().collect(),
            scope: SiteScope::Unrestricted,
            actor,
        }
    }
}

impl crate::AppState {
    /// Resolve what this actor may do and where, live on every request.
    ///
    /// Live rather than session-denormalized on purpose: revoking a
    /// permission or narrowing a scope must bite on the *next request*, not
    /// at the next login. The cost is one indexed lookup beside the session
    /// check the middleware already made.
    ///
    /// Fallback ladder, each step the pre-GP-2 behavior of the one before:
    /// no console-user id (shared admin, magic link, CLI) → unrestricted;
    /// no permission-set store wired → role preset, unscoped; no custom set
    /// assigned (or its row is gone) → role preset; otherwise the set.
    pub async fn resolve_principal(&self, actor: &Actor) -> Principal {
        let role_preset = || {
            chalk_core::models::permission::preset_for(actor.role)
                .into_iter()
                .collect::<HashSet<_>>()
        };
        let Some(user_id) = actor.console_user_id() else {
            return Principal::unrestricted(actor.clone());
        };
        let Some(store) = &self.permission_sets else {
            return Principal {
                permissions: role_preset(),
                scope: SiteScope::Unrestricted,
                actor: actor.clone(),
            };
        };
        let authz = match store.get_console_authz(user_id).await {
            Ok(Some(a)) => a,
            // No row (user deleted mid-session) or a store error: the role
            // preset with no scope restriction matches pre-GP-2 behavior,
            // and an error must not widen a scoped user — so scope only
            // narrows when we positively read grants.
            _ => chalk_core::models::permission::ConsoleAuthz::default(),
        };
        let permissions = match &authz.permission_set_id {
            Some(set_id) => match store.get_permission_set(set_id).await {
                Ok(Some(set)) => set.permissions.into_iter().collect(),
                // The assigned set is unreadable: fall back to the role
                // preset rather than locking the account out entirely.
                _ => role_preset(),
            },
            None => role_preset(),
        };
        Principal {
            permissions,
            scope: authz.site_scope(),
            actor: actor.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
