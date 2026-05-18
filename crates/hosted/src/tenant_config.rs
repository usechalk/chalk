//! `TenantConfigRepo` adapter that seals/unseals secret material via
//! `keys::MasterKey` at the impl boundary.
//!
//! The `chalk-core` `PostgresRepository` stores the `*_sealed` columns as
//! opaque bytes — it has no awareness of the master key (core cannot depend on
//! the hosted crate). This wrapper bridges that: writes call `seal` before
//! delegating, and reads call `unseal` after. From a caller's perspective the
//! returned `*Record` values carry plaintext secret bytes.
//!
//! If `unseal` fails on a stored ciphertext (tamper / wrong key) the wrapper
//! returns an error rather than silently masking the secret — operators must
//! see corruption loudly. See the negative test in
//! `crates/hosted/tests/tenant_config_sealing.rs`.

use async_trait::async_trait;
use chalk_core::db::repository::{
    AdSyncConfigRecord, GoogleSyncConfigRecord, IdpConfigRecord, SisConfigRecord, TenantConfigRepo,
};
use chalk_core::error::{ChalkError, Result};
use std::sync::Arc;

use crate::keys::{seal, unseal, MasterKey};

/// Wraps an inner `TenantConfigRepo` and applies AES-256-GCM seal/unseal to
/// the secret-bearing fields. Clone-able for the per-tenant context.
#[derive(Clone)]
pub struct SealingTenantConfigRepo {
    inner: Arc<dyn TenantConfigRepo>,
    master_key: MasterKey,
}

impl SealingTenantConfigRepo {
    pub fn new(inner: Arc<dyn TenantConfigRepo>, master_key: MasterKey) -> Self {
        Self { inner, master_key }
    }

    fn seal_opt(&self, plaintext: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        match plaintext {
            // Treat empty as unset — sealing `b""` produces a valid (non-empty)
            // ciphertext that would round-trip as `Some(b"")`, blanking the
            // downstream config field on the next load.
            None | Some(b"") => Ok(None),
            Some(bytes) => seal(&self.master_key, bytes)
                .map(Some)
                .map_err(|e| ChalkError::Crypto(format!("seal failed: {e}"))),
        }
    }

    fn unseal_opt(&self, sealed: Option<Vec<u8>>) -> Result<Option<Vec<u8>>> {
        match sealed {
            None => Ok(None),
            Some(ref bytes) if bytes.is_empty() => Ok(None),
            Some(bytes) => unseal(&self.master_key, &bytes)
                .map(Some)
                .map_err(|e| ChalkError::Crypto(format!("unseal failed: {e}"))),
        }
    }
}

#[async_trait]
impl TenantConfigRepo for SealingTenantConfigRepo {
    async fn get_sis_config(&self) -> Result<Option<SisConfigRecord>> {
        let Some(mut r) = self.inner.get_sis_config().await? else {
            return Ok(None);
        };
        r.powerschool_client_secret = self.unseal_opt(r.powerschool_client_secret)?;
        r.infinite_campus_client_secret = self.unseal_opt(r.infinite_campus_client_secret)?;
        r.skyward_client_secret = self.unseal_opt(r.skyward_client_secret)?;
        Ok(Some(r))
    }

    async fn put_sis_config(&self, mut record: SisConfigRecord, actor: &str) -> Result<()> {
        record.powerschool_client_secret =
            self.seal_opt(record.powerschool_client_secret.as_deref())?;
        record.infinite_campus_client_secret =
            self.seal_opt(record.infinite_campus_client_secret.as_deref())?;
        record.skyward_client_secret = self.seal_opt(record.skyward_client_secret.as_deref())?;
        self.inner.put_sis_config(record, actor).await
    }

    async fn get_google_sync_config(&self) -> Result<Option<GoogleSyncConfigRecord>> {
        let Some(mut r) = self.inner.get_google_sync_config().await? else {
            return Ok(None);
        };
        r.service_account_key = self.unseal_opt(r.service_account_key)?;
        Ok(Some(r))
    }

    async fn put_google_sync_config(
        &self,
        mut record: GoogleSyncConfigRecord,
        actor: &str,
    ) -> Result<()> {
        record.service_account_key = self.seal_opt(record.service_account_key.as_deref())?;
        self.inner.put_google_sync_config(record, actor).await
    }

    async fn get_idp_config(&self) -> Result<Option<IdpConfigRecord>> {
        let Some(mut r) = self.inner.get_idp_config().await? else {
            return Ok(None);
        };
        r.saml_cert = self.unseal_opt(r.saml_cert)?;
        r.saml_signing_key = self.unseal_opt(r.saml_signing_key)?;
        Ok(Some(r))
    }

    async fn put_idp_config(&self, mut record: IdpConfigRecord, actor: &str) -> Result<()> {
        record.saml_cert = self.seal_opt(record.saml_cert.as_deref())?;
        record.saml_signing_key = self.seal_opt(record.saml_signing_key.as_deref())?;
        self.inner.put_idp_config(record, actor).await
    }

    async fn get_ad_sync_config(&self) -> Result<Option<AdSyncConfigRecord>> {
        let Some(mut r) = self.inner.get_ad_sync_config().await? else {
            return Ok(None);
        };
        r.bind_password = self.unseal_opt(r.bind_password)?;
        r.tls_ca_cert = self.unseal_opt(r.tls_ca_cert)?;
        Ok(Some(r))
    }

    async fn put_ad_sync_config(&self, mut record: AdSyncConfigRecord, actor: &str) -> Result<()> {
        record.bind_password = self.seal_opt(record.bind_password.as_deref())?;
        record.tls_ca_cert = self.seal_opt(record.tls_ca_cert.as_deref())?;
        self.inner.put_ad_sync_config(record, actor).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chalk_core::db::sqlite::SqliteRepository;
    use chalk_core::db::DatabasePool;

    async fn make_inner() -> Arc<dyn TenantConfigRepo> {
        let pool = DatabasePool::new_sqlite_memory().await.unwrap();
        match pool {
            DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
            DatabasePool::Postgres(_) => unreachable!(),
        }
    }

    #[tokio::test]
    async fn sis_seal_round_trip() {
        let inner = make_inner().await;
        let key = MasterKey::generate();
        let repo = SealingTenantConfigRepo::new(inner.clone(), key);

        let record = SisConfigRecord {
            enabled: true,
            provider: Some("powerschool".into()),
            powerschool_client_secret: Some(b"super-secret".to_vec()),
            ..Default::default()
        };
        repo.put_sis_config(record.clone(), "actor").await.unwrap();

        // Underlying row stores sealed bytes, not plaintext.
        let raw = inner.get_sis_config().await.unwrap().unwrap();
        assert!(raw.powerschool_client_secret.is_some());
        assert_ne!(
            raw.powerschool_client_secret.as_deref(),
            Some(&b"super-secret"[..])
        );

        // Wrapped read returns plaintext.
        let got = repo.get_sis_config().await.unwrap().unwrap();
        assert_eq!(
            got.powerschool_client_secret.as_deref(),
            Some(&b"super-secret"[..])
        );
    }

    #[tokio::test]
    async fn google_seal_round_trip() {
        let inner = make_inner().await;
        let key = MasterKey::generate();
        let repo = SealingTenantConfigRepo::new(inner, key);

        let record = GoogleSyncConfigRecord {
            enabled: true,
            service_account_key: Some(b"{\"k\":\"v\"}".to_vec()),
            ..Default::default()
        };
        repo.put_google_sync_config(record, "actor").await.unwrap();

        let got = repo.get_google_sync_config().await.unwrap().unwrap();
        assert_eq!(
            got.service_account_key.as_deref(),
            Some(&b"{\"k\":\"v\"}"[..])
        );
    }

    #[tokio::test]
    async fn wrong_key_unseal_errors() {
        let inner = make_inner().await;
        let k1 = MasterKey::generate();
        let k2 = MasterKey::generate();

        let writer = SealingTenantConfigRepo::new(inner.clone(), k1);
        let reader = SealingTenantConfigRepo::new(inner, k2);

        let record = SisConfigRecord {
            enabled: true,
            powerschool_client_secret: Some(b"x".to_vec()),
            ..Default::default()
        };
        writer.put_sis_config(record, "actor").await.unwrap();

        let err = reader.get_sis_config().await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unseal failed"), "msg = {msg}");
    }

    #[tokio::test]
    async fn empty_db_returns_none() {
        let inner = make_inner().await;
        let key = MasterKey::generate();
        let repo = SealingTenantConfigRepo::new(inner, key);
        assert!(repo.get_sis_config().await.unwrap().is_none());
        assert!(repo.get_google_sync_config().await.unwrap().is_none());
        assert!(repo.get_idp_config().await.unwrap().is_none());
        assert!(repo.get_ad_sync_config().await.unwrap().is_none());
    }
}
