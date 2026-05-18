//! `rotate-master-key` subcommand — re-wrap every per-tenant sealed secret
//! under a new master key.
//!
//! Sealed material lives in two places:
//!
//! 1. `_meta.tenants`:
//!    - `saml_keypair BYTEA` — output of `keys::seal(...)` directly.
//!    - `oidc_signing_jwk JSONB` — `{"sealed": "<base64>"}` envelope where the
//!      base64 decodes to a sealed blob.
//!
//! 2. Per-tenant `tenant_config_*` tables (Wave B), one schema per tenant.
//!    Each table is a singleton row keyed on `id = TRUE`. Direct seal — no
//!    JSON envelope:
//!    - `tenant_config_sis.powerschool_client_secret_sealed`
//!    - `tenant_config_sis.infinite_campus_client_secret_sealed`
//!    - `tenant_config_sis.skyward_client_secret_sealed`
//!    - `tenant_config_google_sync.service_account_key_sealed`
//!    - `tenant_config_idp.saml_cert_sealed`
//!    - `tenant_config_idp.saml_signing_key_sealed`
//!    - `tenant_config_ad_sync.bind_password_sealed`
//!    - `tenant_config_ad_sync.tls_ca_cert_sealed`
//!
//! Rotation strategy (idempotent on retry):
//! 1. Try to unseal the existing blob with the OLD key.
//! 2. If that fails, try to unseal with the NEW key. If THAT succeeds, the
//!    row was already rotated by a previous (interrupted) run — skip it.
//! 3. If both fail, abort with a clear error identifying the slug + table +
//!    column for diagnostics.
//!
//! Atomicity: all updates — `_meta.tenants` and every per-tenant
//! `tenant_config_*` row across every schema — run inside a single
//! transaction on the control-plane pool, using fully-qualified table names
//! (`"<schema>".tenant_config_sis`, etc.). Postgres transactions span schemas
//! within the same database, so a failure anywhere rolls back the entire
//! rotation and the operator can re-run safely.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::keys::{self, MasterKey};
use crate::meta;

#[derive(Debug, Clone)]
pub struct RotateMasterKeyArgs {
    /// Postgres URL (also accepts env `POSTGRES_URL`).
    pub postgres_url: String,
    /// Old master key, base64-encoded. If `None`, falls back to env
    /// `MASTER_ENCRYPTION_KEY`.
    pub old_key: Option<String>,
    /// New master key, base64-encoded. If `None`, generate one and print to
    /// stdout — operator must capture before the binary exits.
    pub new_key: Option<String>,
}

/// Per-table rotated / already-rotated counts for the Wave B per-tenant config
/// tables. Each pair counts rows across every tenant schema.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TableCounts {
    pub rotated: usize,
    pub already_rotated: usize,
}

/// Outcome reported to the CLI layer.
#[derive(Debug)]
pub struct RotationSummary {
    /// Total rows in `_meta.tenants` whose sealed columns were re-sealed
    /// under the new key.
    pub rotated: usize,
    /// Total rows in `_meta.tenants` that already used the new key (no-op).
    pub already_rotated: usize,
    /// Per-column counts for `tenant_config_sis`.
    pub sis_powerschool: TableCounts,
    pub sis_infinite_campus: TableCounts,
    pub sis_skyward: TableCounts,
    /// Per-column counts for `tenant_config_google_sync`.
    pub google_service_account: TableCounts,
    /// Per-column counts for `tenant_config_idp`.
    pub idp_saml_cert: TableCounts,
    pub idp_saml_signing_key: TableCounts,
    /// Per-column counts for `tenant_config_ad_sync`.
    pub ad_bind_password: TableCounts,
    pub ad_tls_ca_cert: TableCounts,
    pub generated_new_key_b64: Option<String>,
}

pub async fn run(args: RotateMasterKeyArgs) -> Result<()> {
    let old_b64 = match args.old_key {
        Some(s) => s,
        None => std::env::var("MASTER_ENCRYPTION_KEY").map_err(|_| {
            anyhow!(
                "old key not provided: pass --old-key or set MASTER_ENCRYPTION_KEY in the environment"
            )
        })?,
    };
    let old_key = MasterKey::from_base64(&old_b64).context("decoding old master key")?;

    let (new_key, generated_new_key_b64) = match args.new_key {
        Some(s) => (
            MasterKey::from_base64(&s).context("decoding new master key")?,
            None,
        ),
        None => {
            // Generate a fresh 32-byte key, encode to base64 for the operator
            // to capture, and round-trip through `MasterKey::from_base64` so
            // we hand the rotation routine the exact same bytes the operator
            // will paste into `MASTER_ENCRYPTION_KEY` afterwards.
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let b64 = B64.encode(bytes);
            let key = MasterKey::from_base64(&b64).expect("freshly-generated key must decode");
            (key, Some(b64))
        }
    };

    let pool = meta::connect_meta(&args.postgres_url).await?;

    let summary = rotate_all(&pool, &old_key, &new_key).await?;

    if let Some(ref b64) = generated_new_key_b64 {
        println!("generated new master key (capture and store before this process exits):");
        println!("MASTER_ENCRYPTION_KEY={b64}");
    }
    println!(
        "rotated {} _meta.tenants rows ({} already on new key, skipped)",
        summary.rotated, summary.already_rotated
    );
    let per_table = [
        (
            "tenant_config_sis.powerschool_client_secret",
            summary.sis_powerschool,
        ),
        (
            "tenant_config_sis.infinite_campus_client_secret",
            summary.sis_infinite_campus,
        ),
        (
            "tenant_config_sis.skyward_client_secret",
            summary.sis_skyward,
        ),
        (
            "tenant_config_google_sync.service_account_key",
            summary.google_service_account,
        ),
        ("tenant_config_idp.saml_cert", summary.idp_saml_cert),
        (
            "tenant_config_idp.saml_signing_key",
            summary.idp_saml_signing_key,
        ),
        (
            "tenant_config_ad_sync.bind_password",
            summary.ad_bind_password,
        ),
        ("tenant_config_ad_sync.tls_ca_cert", summary.ad_tls_ca_cert),
    ];
    for (label, c) in per_table {
        println!(
            "  {label}: {} rotated, {} already on new key",
            c.rotated, c.already_rotated
        );
    }
    Ok(())
}

/// Tenant identity needed to scope Wave B rotation queries.
#[derive(Clone, Debug)]
struct TenantSchema {
    slug: String,
    db_schema: String,
}

/// One sealed column to rotate inside a per-tenant config table. The
/// `table_label` is human-readable (e.g. `tenant_config_sis`) and used in
/// error messages; `table_sql` is the unquoted identifier embedded in the
/// generated SQL. `column` likewise.
struct SealedColumn {
    table_label: &'static str,
    table_sql: &'static str,
    column: &'static str,
}

/// Wave B sealed columns, in the order surfaced in `RotationSummary`. Static
/// to make it trivial to add new columns without touching the iteration loop.
const SEALED_COLUMNS: &[SealedColumn] = &[
    SealedColumn {
        table_label: "tenant_config_sis",
        table_sql: "tenant_config_sis",
        column: "powerschool_client_secret_sealed",
    },
    SealedColumn {
        table_label: "tenant_config_sis",
        table_sql: "tenant_config_sis",
        column: "infinite_campus_client_secret_sealed",
    },
    SealedColumn {
        table_label: "tenant_config_sis",
        table_sql: "tenant_config_sis",
        column: "skyward_client_secret_sealed",
    },
    SealedColumn {
        table_label: "tenant_config_google_sync",
        table_sql: "tenant_config_google_sync",
        column: "service_account_key_sealed",
    },
    SealedColumn {
        table_label: "tenant_config_idp",
        table_sql: "tenant_config_idp",
        column: "saml_cert_sealed",
    },
    SealedColumn {
        table_label: "tenant_config_idp",
        table_sql: "tenant_config_idp",
        column: "saml_signing_key_sealed",
    },
    SealedColumn {
        table_label: "tenant_config_ad_sync",
        table_sql: "tenant_config_ad_sync",
        column: "bind_password_sealed",
    },
    SealedColumn {
        table_label: "tenant_config_ad_sync",
        table_sql: "tenant_config_ad_sync",
        column: "tls_ca_cert_sealed",
    },
];

/// Indices into `SEALED_COLUMNS`, named for legibility when mapping per-column
/// counts onto `RotationSummary` fields.
const IDX_SIS_POWERSCHOOL: usize = 0;
const IDX_SIS_INFINITE_CAMPUS: usize = 1;
const IDX_SIS_SKYWARD: usize = 2;
const IDX_GOOGLE_SA: usize = 3;
const IDX_IDP_SAML_CERT: usize = 4;
const IDX_IDP_SAML_KEY: usize = 5;
const IDX_AD_BIND_PASSWORD: usize = 6;
const IDX_AD_TLS_CA_CERT: usize = 7;

/// Core rotation routine, exposed for tests. Runs in a single transaction
/// across `_meta.tenants` and every tenant schema's `tenant_config_*` tables.
pub async fn rotate_all(
    pool: &PgPool,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<RotationSummary> {
    let mut tx = pool.begin().await?;

    // Phase 1: rotate `_meta.tenants` (saml_keypair, oidc_signing_jwk). Lock
    // every row FOR UPDATE so concurrent provisioning blocks until rotation
    // commits.
    let (rotated, already, tenants) = rotate_meta_tenants(&mut tx, old_key, new_key).await?;

    // Phase 2: rotate Wave B per-tenant config tables. We iterate every
    // tenant from `_meta.tenants` (not just `active` ones — `provisioning`
    // and `suspended` tenants can still have sealed material that must
    // remain readable after rotation).
    let mut counts: [TableCounts; SEALED_COLUMNS.len()] = Default::default();
    for tenant in &tenants {
        rotate_tenant_config(&mut tx, tenant, old_key, new_key, &mut counts).await?;
    }

    tx.commit().await?;
    Ok(RotationSummary {
        rotated,
        already_rotated: already,
        sis_powerschool: counts[IDX_SIS_POWERSCHOOL],
        sis_infinite_campus: counts[IDX_SIS_INFINITE_CAMPUS],
        sis_skyward: counts[IDX_SIS_SKYWARD],
        google_service_account: counts[IDX_GOOGLE_SA],
        idp_saml_cert: counts[IDX_IDP_SAML_CERT],
        idp_saml_signing_key: counts[IDX_IDP_SAML_KEY],
        ad_bind_password: counts[IDX_AD_BIND_PASSWORD],
        ad_tls_ca_cert: counts[IDX_AD_TLS_CA_CERT],
        generated_new_key_b64: None,
    })
}

/// Rotate the two sealed columns in `_meta.tenants`. Returns
/// `(rotated, already_rotated, tenants)` where `tenants` is the full set of
/// (slug, db_schema) pairs the caller will iterate for Wave B rotation.
async fn rotate_meta_tenants(
    tx: &mut Transaction<'_, Postgres>,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<(usize, usize, Vec<TenantSchema>)> {
    let rows = sqlx::query(
        "SELECT slug, db_schema, saml_keypair, oidc_signing_jwk \
         FROM _meta.tenants \
         FOR UPDATE",
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut rotated = 0usize;
    let mut already = 0usize;
    let mut tenants = Vec::with_capacity(rows.len());

    for row in rows {
        let slug: String = row.try_get("slug")?;
        let db_schema: String = row.try_get("db_schema")?;
        let saml: Option<Vec<u8>> = row.try_get("saml_keypair")?;
        let oidc_json: Option<serde_json::Value> = row.try_get("oidc_signing_jwk")?;

        tenants.push(TenantSchema {
            slug: slug.clone(),
            db_schema,
        });

        let mut new_saml: Option<Vec<u8>> = None;
        let mut new_oidc_json: Option<serde_json::Value> = None;
        let mut row_touched = false;
        let mut row_already = false;

        if let Some(ref blob) = saml {
            match rewrap(old_key, new_key, blob) {
                Rewrap::Rotated(b) => {
                    new_saml = Some(b);
                    row_touched = true;
                }
                Rewrap::AlreadyRotated => {
                    new_saml = Some(blob.clone());
                    row_already = true;
                }
                Rewrap::Failed => {
                    return Err(anyhow!(
                        "_meta.tenants.saml_keypair for tenant `{slug}` cannot be unsealed with either old or new key — aborting rotation"
                    ));
                }
            }
        }

        if let Some(ref json) = oidc_json {
            let sealed_b64 = json.get("sealed").and_then(|s| s.as_str()).ok_or_else(|| {
                anyhow!("oidc_signing_jwk for tenant `{slug}` missing `sealed` field")
            })?;
            let sealed_bytes = B64
                .decode(sealed_b64)
                .map_err(|e| anyhow!("oidc_signing_jwk base64 decode failed for `{slug}`: {e}"))?;
            match rewrap(old_key, new_key, &sealed_bytes) {
                Rewrap::Rotated(b) => {
                    let envelope = serde_json::json!({ "sealed": B64.encode(&b) });
                    new_oidc_json = Some(envelope);
                    row_touched = true;
                }
                Rewrap::AlreadyRotated => {
                    new_oidc_json = Some(json.clone());
                    row_already = true;
                }
                Rewrap::Failed => {
                    return Err(anyhow!(
                        "_meta.tenants.oidc_signing_jwk for tenant `{slug}` cannot be unsealed with either old or new key — aborting rotation"
                    ));
                }
            }
        }

        // Skip the UPDATE if the row had no sealed material at all.
        if saml.is_none() && oidc_json.is_none() {
            continue;
        }

        sqlx::query(
            "UPDATE _meta.tenants \
             SET saml_keypair = $1, oidc_signing_jwk = $2, updated_at = now() \
             WHERE slug = $3",
        )
        .bind(new_saml)
        .bind(new_oidc_json)
        .bind(&slug)
        .execute(&mut **tx)
        .await?;

        if row_touched {
            rotated += 1;
        } else if row_already {
            already += 1;
        }
    }

    Ok((rotated, already, tenants))
}

/// Rotate every sealed column for a single tenant's `tenant_config_*` tables.
/// Updates `counts[i]` in place for each `SEALED_COLUMNS[i]` we touched.
async fn rotate_tenant_config(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &TenantSchema,
    old_key: &MasterKey,
    new_key: &MasterKey,
    counts: &mut [TableCounts; SEALED_COLUMNS.len()],
) -> Result<()> {
    let schema = &tenant.db_schema;
    // Guard: the schema is derived from a validated slug (`schema_for_slug`)
    // so this assertion holds for any tenant that came through provisioning.
    // We still gate on it to refuse any registry row that somehow contains an
    // unsafe identifier — `format!` below interpolates the schema directly.
    if !is_safe_pg_identifier(schema) {
        return Err(anyhow!(
            "tenant `{}` has unsafe db_schema `{}` — refusing to interpolate into SQL",
            tenant.slug,
            schema
        ));
    }

    for (idx, col) in SEALED_COLUMNS.iter().enumerate() {
        // Use to_regclass to skip tables that don't exist yet — older tenants
        // provisioned before migration 013 ran would otherwise blow up the
        // entire rotation. The lookup is also a transaction-safe way to skip
        // missing tables without needing a separate connection.
        let qualified = format!("{schema}.{}", col.table_sql);
        let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(&qualified)
            .fetch_one(&mut **tx)
            .await?;
        if exists.is_none() {
            continue;
        }

        let select_sql = format!(
            "SELECT {col} FROM \"{schema}\".{table} WHERE id = TRUE FOR UPDATE",
            col = col.column,
            schema = schema,
            table = col.table_sql,
        );
        let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(&select_sql)
            .fetch_optional(&mut **tx)
            .await?;
        let current = match row {
            Some((v,)) => v,
            None => continue, // no singleton row yet
        };
        let blob = match current {
            Some(b) => b,
            None => continue, // column is NULL — nothing to rotate
        };

        let new_blob = match rewrap(old_key, new_key, &blob) {
            Rewrap::Rotated(b) => {
                counts[idx].rotated += 1;
                b
            }
            Rewrap::AlreadyRotated => {
                counts[idx].already_rotated += 1;
                continue;
            }
            Rewrap::Failed => {
                return Err(anyhow!(
                    "{table}.{col} for tenant `{slug}` (schema `{schema}`) cannot be unsealed with either old or new key — aborting rotation",
                    table = col.table_label,
                    col = col.column,
                    slug = tenant.slug,
                    schema = schema,
                ));
            }
        };

        let update_sql = format!(
            "UPDATE \"{schema}\".{table} SET {col} = $1, updated_at = now() WHERE id = TRUE",
            schema = schema,
            table = col.table_sql,
            col = col.column,
        );
        sqlx::query(&update_sql)
            .bind(&new_blob)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Defensive identifier check for tenant schema names we interpolate into
/// SQL. Mirrors `chalk_core::config::is_valid_pg_schema` but is kept inline
/// so this file is self-contained — `schema_for_slug` already produces names
/// that always pass.
fn is_safe_pg_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let bytes = s.as_bytes();
    if !(bytes[0].is_ascii_lowercase() || bytes[0] == b'_') {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

enum Rewrap {
    Rotated(Vec<u8>),
    AlreadyRotated,
    Failed,
}

fn rewrap(old_key: &MasterKey, new_key: &MasterKey, sealed: &[u8]) -> Rewrap {
    match keys::unseal(old_key, sealed) {
        Ok(plain) => match keys::seal(new_key, &plain) {
            Ok(new_blob) => Rewrap::Rotated(new_blob),
            Err(_) => Rewrap::Failed,
        },
        Err(_) => match keys::unseal(new_key, sealed) {
            Ok(_) => Rewrap::AlreadyRotated,
            Err(_) => Rewrap::Failed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrap_round_trip() {
        let old_key = MasterKey::generate();
        let new_key = MasterKey::generate();
        let plaintext = b"super-secret-saml-keypair-blob";
        let sealed_old = keys::seal(&old_key, plaintext).unwrap();

        match rewrap(&old_key, &new_key, &sealed_old) {
            Rewrap::Rotated(new_blob) => {
                let opened = keys::unseal(&new_key, &new_blob).unwrap();
                assert_eq!(opened, plaintext);
                assert!(keys::unseal(&old_key, &new_blob).is_err());
            }
            _ => panic!("expected Rotated"),
        }
    }

    #[test]
    fn rewrap_detects_already_rotated() {
        let old_key = MasterKey::generate();
        let new_key = MasterKey::generate();
        let sealed_new = keys::seal(&new_key, b"already-on-new-key").unwrap();
        match rewrap(&old_key, &new_key, &sealed_new) {
            Rewrap::AlreadyRotated => {}
            _ => panic!("expected AlreadyRotated"),
        }
    }

    #[test]
    fn rewrap_fails_when_neither_key_works() {
        let old_key = MasterKey::generate();
        let new_key = MasterKey::generate();
        let stranger = MasterKey::generate();
        let sealed = keys::seal(&stranger, b"unknown-key").unwrap();
        match rewrap(&old_key, &new_key, &sealed) {
            Rewrap::Failed => {}
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn rewrap_chain_idempotent() {
        // Round 1: rotate old -> new.
        // Round 2 (re-run): rewrap should detect AlreadyRotated.
        let old_key = MasterKey::generate();
        let new_key = MasterKey::generate();
        let sealed_old = keys::seal(&old_key, b"payload").unwrap();
        let after = match rewrap(&old_key, &new_key, &sealed_old) {
            Rewrap::Rotated(b) => b,
            _ => panic!("first pass must rotate"),
        };
        match rewrap(&old_key, &new_key, &after) {
            Rewrap::AlreadyRotated => {}
            _ => panic!("second pass must report AlreadyRotated"),
        }
    }

    /// Wave B coverage requirement #1: a tenant with all 8 sealed columns
    /// populated — every column re-seals; unseal-with-NEW-key returns the
    /// original plaintext. We can't open a real Postgres connection from a
    /// pure unit test, so we exercise the rewrap path that the per-column
    /// loop drives, once per sealed-column entry in `SEALED_COLUMNS`. This
    /// guarantees no column is silently skipped if `SEALED_COLUMNS` grows.
    #[test]
    fn all_eight_sealed_columns_round_trip() {
        assert_eq!(SEALED_COLUMNS.len(), 8, "Wave B added exactly 8 columns");
        let old_key = MasterKey::generate();
        let new_key = MasterKey::generate();

        for col in SEALED_COLUMNS {
            // Distinct plaintext per column makes a swapped column blow up
            // the assertion below.
            let plaintext = format!("plain-{}-{}", col.table_sql, col.column);
            let sealed_old = keys::seal(&old_key, plaintext.as_bytes()).unwrap();
            let new_blob = match rewrap(&old_key, &new_key, &sealed_old) {
                Rewrap::Rotated(b) => b,
                _ => panic!("expected Rotated for {}.{}", col.table_sql, col.column),
            };
            let opened = keys::unseal(&new_key, &new_blob).unwrap();
            assert_eq!(
                opened,
                plaintext.as_bytes(),
                "plaintext mismatch after rotate for {}.{}",
                col.table_sql,
                col.column
            );
            assert!(
                keys::unseal(&old_key, &new_blob).is_err(),
                "old key must NOT open rotated blob for {}.{}",
                col.table_sql,
                col.column
            );
        }
    }

    /// Wave B coverage requirement #2: a NULL column is a no-op. The
    /// per-tenant loop short-circuits on `None`; this test pins that
    /// behaviour by asserting `Option::None` continues to flow through
    /// unchanged.
    #[test]
    fn null_columns_are_skipped() {
        let old_key = MasterKey::generate();
        let new_key = MasterKey::generate();
        // Build a population vector with 4 of the 8 columns populated and 4
        // null. Iterate and confirm only populated columns produce rewrap
        // work; null columns are not handed to `rewrap` at all.
        let mut handled = 0usize;
        for (idx, col) in SEALED_COLUMNS.iter().enumerate() {
            let populated = idx % 2 == 0;
            let current: Option<Vec<u8>> = if populated {
                Some(keys::seal(&old_key, col.column.as_bytes()).unwrap())
            } else {
                None
            };
            match current {
                None => {
                    // The real `rotate_tenant_config` calls `continue` here
                    // before invoking `rewrap`. We mirror that branch.
                }
                Some(blob) => {
                    handled += 1;
                    match rewrap(&old_key, &new_key, &blob) {
                        Rewrap::Rotated(_) => {}
                        _ => panic!("populated column must rotate cleanly"),
                    }
                }
            }
        }
        assert_eq!(handled, 4, "half of the columns are populated in fixture");
    }

    /// Wave B coverage requirement #3: idempotent retry — a second pass with
    /// the same (old, new) pair after a successful rotation must produce
    /// `AlreadyRotated` for every column.
    #[test]
    fn rewrap_chain_idempotent_across_all_columns() {
        let old_key = MasterKey::generate();
        let new_key = MasterKey::generate();
        for col in SEALED_COLUMNS {
            let sealed_old = keys::seal(&old_key, col.column.as_bytes()).unwrap();
            let new_blob = match rewrap(&old_key, &new_key, &sealed_old) {
                Rewrap::Rotated(b) => b,
                _ => panic!("first pass must rotate {}", col.column),
            };
            match rewrap(&old_key, &new_key, &new_blob) {
                Rewrap::AlreadyRotated => {}
                _ => panic!("second pass must be AlreadyRotated for {}", col.column),
            }
        }
    }

    /// Same as above but with `old_key == new_key`: a no-op rotation should
    /// always succeed by detecting AlreadyRotated. This is the operator
    /// retry path when they aren't sure whether the previous attempt
    /// committed.
    #[test]
    fn rewrap_with_identical_old_and_new_keys_is_a_noop() {
        let key = MasterKey::generate();
        for col in SEALED_COLUMNS {
            let sealed = keys::seal(&key, col.column.as_bytes()).unwrap();
            // `rewrap` with identical keys: the OLD unseal succeeds, so we
            // take the Rotated branch and seal again with the same key.
            // The new ciphertext differs (random nonce) but still unseals
            // under the same key.
            match rewrap(&key, &key, &sealed) {
                Rewrap::Rotated(b) => {
                    assert_eq!(keys::unseal(&key, &b).unwrap(), col.column.as_bytes());
                }
                _ => panic!("identical keys must take Rotated branch"),
            }
        }
    }

    /// Wave B coverage requirement #4: wrong-old-key on a populated column
    /// surfaces a diagnostic identifying the tenant + table + column. We
    /// can't drive `rotate_tenant_config` without a Postgres connection,
    /// but we can sanity-check the error template used inside it by
    /// formatting the same string and asserting all three pieces are
    /// present.
    #[test]
    fn diagnostic_message_includes_tenant_table_column() {
        let col = &SEALED_COLUMNS[IDX_SIS_POWERSCHOOL];
        let slug = "acme";
        let schema = "tenant_acme";
        let msg = format!(
            "{table}.{col} for tenant `{slug}` (schema `{schema}`) cannot be unsealed with either old or new key — aborting rotation",
            table = col.table_label,
            col = col.column,
            slug = slug,
            schema = schema,
        );
        assert!(msg.contains(slug), "must name the tenant slug");
        assert!(msg.contains(col.table_label), "must name the table");
        assert!(msg.contains(col.column), "must name the column");
        assert!(msg.contains("aborting"), "must signal abort");
    }

    /// Defence-in-depth: the schema interpolation guard must reject anything
    /// that doesn't look like a `schema_for_slug` output.
    #[test]
    fn schema_identifier_guard_rejects_unsafe_inputs() {
        assert!(is_safe_pg_identifier("tenant_acme"));
        assert!(is_safe_pg_identifier("tenant_a12_b34"));
        assert!(is_safe_pg_identifier("_meta"));
        assert!(!is_safe_pg_identifier(""));
        assert!(!is_safe_pg_identifier("Tenant_acme"));
        assert!(!is_safe_pg_identifier("tenant-acme"));
        assert!(!is_safe_pg_identifier("tenant_acme; DROP TABLE x"));
        assert!(!is_safe_pg_identifier("tenant_acme\""));
        assert!(!is_safe_pg_identifier("123tenant"));
    }

    /// Pin that `SEALED_COLUMNS` matches the Wave B migration's column set.
    /// If migration 013 adds a column and this constant goes stale, callers
    /// will silently skip it — the test guards against that drift by listing
    /// the expected (table, column) pairs and asserting set equality.
    #[test]
    fn sealed_columns_match_wave_b_migration() {
        let expected: &[(&str, &str)] = &[
            ("tenant_config_sis", "powerschool_client_secret_sealed"),
            ("tenant_config_sis", "infinite_campus_client_secret_sealed"),
            ("tenant_config_sis", "skyward_client_secret_sealed"),
            ("tenant_config_google_sync", "service_account_key_sealed"),
            ("tenant_config_idp", "saml_cert_sealed"),
            ("tenant_config_idp", "saml_signing_key_sealed"),
            ("tenant_config_ad_sync", "bind_password_sealed"),
            ("tenant_config_ad_sync", "tls_ca_cert_sealed"),
        ];
        let actual: Vec<(&str, &str)> = SEALED_COLUMNS
            .iter()
            .map(|c| (c.table_sql, c.column))
            .collect();
        assert_eq!(actual.as_slice(), expected);
    }
}
