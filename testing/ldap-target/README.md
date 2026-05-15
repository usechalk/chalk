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

## Known failures (bugs surfaced — `run.sh` will FAIL until fixed)

This scenario is currently a regression test for two bugs in
`chalk-ad-sync` that block the OpenLDAP path. The scenario is intentionally
left FAILING so the bugs stay visible.

**Bug A — `manage_ous = true` does not create missing OUs**
- Symptom: `LDAP search OU error: rc=32 (noSuchObject), dn: "dc=test,dc=local"`
  on the first user.
- Repro: any sync into an empty directory.
- The code searches for the target OU, treats `noSuchObject` as a hard
  error, and never reaches the OU-creation path. With `manage_ous = true`
  the option implies "create what's missing" — that's not what happens.
- Fix sketch: when the OU search returns no results AND `manage_ous` is
  true, issue an `ldap_add` for the OU before adding users. See
  `crates/ad-sync/src/sync.rs` `ensure_ou_exists` (or equivalent).

**Bug B — `objectClass` values rejected by OpenLDAP**
- Symptom: `LDAP add user rejected: rc=21 (invalidAttributeSyntax),
  text: "objectClass: value #N invalid per syntax"`.
- Repro: with the OU pre-created, run ad-sync against OpenLDAP.
- The user entry sends an objectClass list that includes a class
  OpenLDAP's stock schema doesn't know — likely a Microsoft-specific
  one (`user`, `securityPrincipal`, etc.).
- Fix sketch: make objectClass configurable per directory flavor, or
  emit a universally-supported set (`top`, `person`, `organizationalPerson`,
  `inetOrgPerson`) when the bind detects OpenLDAP. AD-only classes can
  layer on under a `target = "active_directory"` flag.

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
