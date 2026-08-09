---
name: new-route
description: Add a console route — handler, permission declaration, scoping, and the lints that enforce both
---

# Adding a console route

## 1. Declare its permission or the build fails

Every route in `crates/console/src/lib.rs` needs an arm in
`route_authz` (`crates/console/src/authz.rs`):
`Public`, `SelfService`, `Read(Permission)`, or `Write(Permission)`.
`scripts/route-permission-lint.sh` (in CI) derives the route list from the
router source and fails on any undeclared path. At runtime, an undeclared
**mutating** route is refused outright by the middleware.

Choosing the permission: match the page-group a district would grant as a
unit (see the `Permission` enum in `crates/core/src/models/permission.rs`).
Form GETs carry the write permission — an edit form the caller can never
submit is a dead end, not a read.

## 2. Site scoping

If the surface lists or mutates school-scoped rows (assets, tickets,
custody, fees):
- **Lists**: run the filter through `principal.scope_asset_filter(...)`
  (assets) or `principal.scope.to_ticket_scope()` (tickets), so pagination
  counts agree with visibility.
- **By-id reads/writes**: after loading the target, check
  `principal.permits_school(row.school_org_sourced_id.as_deref())` and
  answer **not-found** (never 403 — a 403 confirms existence).
- Get the principal with
  `axum::Extension(principal): axum::Extension<crate::authz::Principal>`.

## 3. Forms

axum's `Form<T>` is serde_urlencoded, which **cannot** collect repeated keys
(checkbox grids) into a `Vec` — it 422s. Hand-parse the raw `body: String`
instead, following `unmatched::BulkForm`. The CSRF middleware validates the
`csrf_token` field from the body on its own; `+` means space — decode it
before percent-decoding.

CSRF: the middleware inserts `CsrfToken` on GET only. A POST handler that
re-renders a form must echo the cookie's token via
`crate::csrf::csrf_from_headers(&headers)` — minting a fresh token breaks
the next submit.

## 4. Tests

Router tests drive the real `router()` against the `wire_all` fixture
(`crate::tests::wire_all`) — a partial fixture makes pages 404 for a missing
repository, which reads identically to "route not registered" and has
produced vacuous tests three times. If your surface renders public/shared
content, assert what it must NOT contain too (the dashboard share leaked the
whole sidebar until a test demanded zero console affordances).

## 5. Sidebar

A link is only added when the route serves (module-gated with the same flag).
The sidebar-crawl test walks every link `base.html` renders and fails on a
404 — but it can't notice a page nobody links to, so remember the link.
