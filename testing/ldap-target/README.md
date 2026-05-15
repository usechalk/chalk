# LDAP / AD sync scenario

End-to-end exercise of the `chalk ad-sync` CLI: bind to a real LDAP server,
provision users derived from synced roster data, verify they land in the
directory.

## What this proves

✅ `chalk ad-sync --test-connection` binds to a real LDAP server.

✅ `chalk ad-sync` reads users from the local SQLite DB and creates real
   LDAP entries (no mocking).

✅ The OU mapping config (`students = "..."`, `teachers = "..."`) actually
   places users in the right containers.

## What this does NOT prove

⚠️ Real Active Directory specifics. We use OpenLDAP, which is API-compatible
   with AD's LDAP surface but doesn't enforce AD's schema constraints
   (sAMAccountName length, objectClass requirements for `user` vs
   `inetOrgPerson`, password complexity policy, etc.). If your real target
   is Active Directory, also test against a real AD before relying on this.

⚠️ TLS / Kerberos. The container speaks plain LDAP on `:1389`. Production
   binds typically need LDAPS or StartTLS plus a CA cert.

⚠️ Group provisioning. The default config in `run.sh` enables
   `manage_ous = true` but `manage_groups = false`. Group membership sync
   isn't exercised.

## Bugs that this scenario originally surfaced (now fixed)

Earlier runs of this scenario surfaced two bugs in `chalk-ad-sync` that
blocked the OpenLDAP path. Both are fixed in the current main:

**Bug A — `manage_ous = true` did not create missing OUs**
- The `ensure_ou_exists` implementation in
  `crates/ad-sync/src/client.rs` did a `Scope::Base` search on the OU's
  own DN, called `.success()` on the result, and bailed on `rc=32
  (noSuchObject)` instead of falling through to the create path.
- Fix: catch `LdapError::LdapResult { result }` where `result.rc == 32`
  specifically, log a debug, and proceed to the `ldap_add` for the OU.

**Bug B — `objectClass` values rejected by OpenLDAP**
- `create_user` always emitted `objectClass=[top, person,
  organizationalPerson, user]` plus `sAMAccountName`,
  `userAccountControl`, and `unicodePwd` — all Microsoft-specific.
- Fix: new `[ad_sync.options] schema = "open_ldap" | "active_directory"`
  config (default `active_directory` — preserves existing behavior). On
  the OpenLDAP path the client emits `inetOrgPerson` with `uid` /
  `userPassword` and skips the AD-only attrs, and `user_dn_for(...)`
  builds `uid=...,ou=...,...` instead of `CN=...,ou=...,...`.

The current `run.sh` sets `schema = "open_ldap"` in its temp config and
expects PASS. If it ever regresses, both bugs will surface here first.

## Prerequisites

- Docker + Docker Compose (for the OpenLDAP container).
- `ldapsearch` on PATH (`apt install ldap-utils` / `brew install openldap`).
  Used to verify what landed in LDAP from outside the container.

## Run

```bash
./run.sh
```

The script:
1. Brings up `bitnami/openldap` on `localhost:1389`, root dn `dc=test,dc=local`.
2. Imports `../oneroster-csv/data/` into a temp SQLite DB.
3. Generates a temp `chalk.toml` pointing AD sync at the container.
4. `chalk ad-sync --test-connection` — assert success.
5. `chalk ad-sync` — provision users.
6. `ldapsearch` against the container — assert all 5 users present.
7. `docker compose down` (always — even on failure or interrupt).

## Layout

```
ldap-target/
├── README.md
├── docker-compose.yml      # bitnami/openldap on :1389
└── run.sh                  # up → import → ad-sync → ldapsearch → down
```
