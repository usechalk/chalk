//! `rotate-master-key` subcommand — re-wrap every per-tenant sealed secret
//! under a new master key.
//!
//! Sealed material lives in two columns of `_meta.tenants`:
//! - `saml_keypair BYTEA` — output of `keys::seal(...)` directly.
//! - `oidc_signing_jwk JSONB` — `{"sealed": "<base64>"}` envelope where the
//!   base64 decodes to a sealed blob.
//!
//! Rotation strategy (idempotent on retry):
//! 1. Try to unseal the existing blob with the OLD key.
//! 2. If that fails, try to unseal with the NEW key. If THAT succeeds, the
//!    row was already rotated by a previous (interrupted) run — skip it.
//! 3. If both fail, abort with a clear error identifying the slug.
//!
//! All updates run inside a single Postgres transaction; on error we roll
//! back and the operator can re-run safely.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sqlx::Row;

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

/// Outcome reported to the CLI layer.
#[derive(Debug)]
pub struct RotationSummary {
    pub rotated: usize,
    pub already_rotated: usize,
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
        "rotated {} tenant secret rows ({} already on new key, skipped)",
        summary.rotated, summary.already_rotated
    );
    Ok(())
}

/// Core rotation routine, exposed for tests. Runs in a single transaction.
pub async fn rotate_all(
    pool: &sqlx::PgPool,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<RotationSummary> {
    let mut tx = pool.begin().await?;

    let rows = sqlx::query(
        "SELECT slug, saml_keypair, oidc_signing_jwk \
         FROM _meta.tenants \
         FOR UPDATE",
    )
    .fetch_all(&mut *tx)
    .await?;

    let mut rotated = 0usize;
    let mut already = 0usize;

    for row in rows {
        let slug: String = row.try_get("slug")?;
        let saml: Option<Vec<u8>> = row.try_get("saml_keypair")?;
        let oidc_json: Option<serde_json::Value> = row.try_get("oidc_signing_jwk")?;

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
                        "saml_keypair for tenant `{slug}` cannot be unsealed with either old or new key — aborting rotation"
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
                        "oidc_signing_jwk for tenant `{slug}` cannot be unsealed with either old or new key — aborting rotation"
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
        .execute(&mut *tx)
        .await?;

        if row_touched {
            rotated += 1;
        } else if row_already {
            already += 1;
        }
    }

    tx.commit().await?;
    Ok(RotationSummary {
        rotated,
        already_rotated: already,
        generated_new_key_b64: None,
    })
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
}
