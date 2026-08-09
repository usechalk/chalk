---
name: migration
description: Add a database migration — paired SQLite/Postgres files, registration, the semicolon rule, and the guards
---

# Adding a migration

## The rules the guards enforce

1. **Two files, same number and name**: `migrations/sqlite/0NN_name.sql` and
   `migrations/postgres/0NN_name.sql`. Types differ (`TEXT` timestamps in
   SQLite, `TIMESTAMPTZ` in Postgres; `INTEGER` vs `BIGINT`/`BOOLEAN`).
2. **No semicolons in comments.** The SQLite runner splits on `;` — a
   semicolon inside a comment truncates the statement after it. The guard
   test `sqlite_migrations_have_no_semicolons_in_comments` fails the suite;
   it has caught this four separate times. Write comments without them, use
   `--` dashes for punctuation.
3. **Register in BOTH arms** of `crates/core/src/db/mod.rs`: the postgres
   list uses the bare name (`"0NN_name"`), the sqlite list keeps the suffix
   (`"0NN_name.sql"`). The migration-count guard tests fail if one arm is
   missing.
4. Postgres DDL should be idempotent (`IF NOT EXISTS`, `ADD COLUMN IF NOT
   EXISTS`) — hosted runs migrations per tenant schema on every deploy.

## Naming reality checks

Foreign keys must reference the table's **actual** name — check the earlier
migration, not your memory (`repairs` is really `repair_records`; the
tenants meta table column is `db_schema`, not `schema_name`).

## After the schema: the model thread

A new column threads through, in order:
- the model struct + `::new()` + `Patch` enum + `set_clauses` push
  (`crates/core/src/models/…`)
- both drivers' row mapper, INSERT column list + placeholders + binds, and
  UPDATE — **count the placeholders**; a mismatch is a runtime error, not a
  compile error, and only the round-trip test catches it
- the round-trip test fixture (`full_asset` / equivalent) so a driver
  dropping the field fails the suite

When editing driver SQL with scripted replaces, anchor on the full statement
text: generic patterns like `VALUES (?1..?8)` appear on many tables and the
first match is usually not yours.

## Repository additions

New tables get a trait in `crates/core/src/db/repository.rs` implemented in
both drivers. Then:
- `AppState` builder (`with_*`) in the console
- `wire_all` in the console tests module — the fixture must stay as wired
  as production
- `chalk serve` — `crates/cli/tests/serve_wiring.rs` FAILS until you wire it
  or add a documented hosted-only exception
- hosted needs a `TenantScoped*` wrapper (see `hosted-release` skill)
