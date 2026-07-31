//! A `TenantConfigRepo` adapter that seals secret material at the repository
//! boundary.
//!
//! # Why this exists in core
//!
//! The raw `SqliteRepository` / `PostgresRepository` implementations store the
//! `*_sealed` columns as opaque bytes — they have no awareness of a master key,
//! and should not. Something has to encrypt on the way in and decrypt on the
//! way out, and until now the only implementation of that lived in the hosted
//! crate. That is why a self-hosted install wires `tenant_config` as `None`
//! and its settings pages render "not configured": there was no sealer.
//!
//! Putting it here means one implementation serves both deployments, and — the
//! reason it matters for the device module — a self-hoster can store a Google
//! service-account key through the console instead of editing a filesystem
//! path into TOML.
//!
//! # What "sealed" means at each layer
//!
//! From a caller's perspective the `*Record` types always carry **plaintext**
//! secret bytes. The ciphertext exists only between this wrapper and the
//! database. That is why the record fields are named `service_account_key`
//! while the columns are named `service_account_key_sealed`.
//!
//! # Failure is loud
//!
//! If unsealing fails — a wrong master key, a truncated column, tampering —
//! this returns an error rather than a `None` that would look like "not
//! configured". An operator restoring a database with the wrong `chalk.key`
//! must see a decryption failure, not a console that quietly offers to set up
//! Google again while the real credential sits unreadable in the table.

use std::sync::Arc;

use async_trait::async_trait;

use crate::crypto;
use crate::db::repository::{
    AdSyncConfigRecord, DeviceConfigRecord, GoogleSyncConfigRecord, IdpConfigRecord,
    SisConfigRecord, TenantConfigRepo,
};
use crate::error::{ChalkError, Result};

/// Wraps a `TenantConfigRepo`, applying AES-256-GCM to the secret-bearing
/// fields.
pub struct SealingConfigRepo {
    inner: Arc<dyn TenantConfigRepo>,
    master_key: [u8; 32],
}

impl SealingConfigRepo {
    pub fn new(inner: Arc<dyn TenantConfigRepo>, master_key: [u8; 32]) -> Self {
        Self { inner, master_key }
    }

    /// Read a 32-byte master key from disk — `chalk.key`, which `chalk init`
    /// generates.
    ///
    /// The length is checked rather than truncated. A short or padded file is
    /// almost always the wrong file, and silently accepting it would encrypt
    /// every secret under a key nobody can reproduce.
    pub fn load_key(path: &std::path::Path) -> Result<[u8; 32]> {
        let bytes = std::fs::read(path).map_err(|e| {
            ChalkError::Crypto(format!("could not read master key {}: {e}", path.display()))
        })?;
        bytes.as_slice().try_into().map_err(|_| {
            ChalkError::Crypto(format!(
                "master key {} is {} bytes, expected exactly 32",
                path.display(),
                bytes.len()
            ))
        })
    }

    fn seal(&self, plaintext: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        match plaintext {
            // Empty is unset. Sealing `b""` produces a valid, non-empty
            // ciphertext that would round-trip as `Some(b"")` — and a caller
            // checking `is_some()` to decide whether a credential is on file
            // would then be told yes about an empty one.
            None | Some(b"") => Ok(None),
            Some(bytes) => crypto::encrypt(&self.master_key, bytes).map(Some),
        }
    }

    fn unseal(&self, sealed: Option<Vec<u8>>) -> Result<Option<Vec<u8>>> {
        match sealed {
            None => Ok(None),
            // Mirrors the seal rule. A real ciphertext is always at least 28
            // bytes (12-byte nonce + 16-byte GCM tag), so an empty cell can
            // only come from hand-written SQL or a migration bug — treat it as
            // unset rather than failing a whole config read over it.
            Some(bytes) if bytes.is_empty() => Ok(None),
            Some(bytes) => crypto::decrypt(&self.master_key, &bytes).map(Some),
        }
    }
}

#[async_trait]
impl TenantConfigRepo for SealingConfigRepo {
    async fn get_sis_config(&self) -> Result<Option<SisConfigRecord>> {
        let Some(mut r) = self.inner.get_sis_config().await? else {
            return Ok(None);
        };
        r.powerschool_client_secret = self.unseal(r.powerschool_client_secret)?;
        r.infinite_campus_client_secret = self.unseal(r.infinite_campus_client_secret)?;
        r.skyward_client_secret = self.unseal(r.skyward_client_secret)?;
        Ok(Some(r))
    }

    async fn put_sis_config(&self, mut record: SisConfigRecord, actor: &str) -> Result<()> {
        record.powerschool_client_secret =
            self.seal(record.powerschool_client_secret.as_deref())?;
        record.infinite_campus_client_secret =
            self.seal(record.infinite_campus_client_secret.as_deref())?;
        record.skyward_client_secret = self.seal(record.skyward_client_secret.as_deref())?;
        self.inner.put_sis_config(record, actor).await
    }

    async fn get_google_sync_config(&self) -> Result<Option<GoogleSyncConfigRecord>> {
        let Some(mut r) = self.inner.get_google_sync_config().await? else {
            return Ok(None);
        };
        r.service_account_key = self.unseal(r.service_account_key)?;
        Ok(Some(r))
    }

    async fn put_google_sync_config(
        &self,
        mut record: GoogleSyncConfigRecord,
        actor: &str,
    ) -> Result<()> {
        record.service_account_key = self.seal(record.service_account_key.as_deref())?;
        self.inner.put_google_sync_config(record, actor).await
    }

    async fn get_device_config(&self) -> Result<Option<DeviceConfigRecord>> {
        let Some(mut r) = self.inner.get_device_config().await? else {
            return Ok(None);
        };
        r.service_account_key = self.unseal(r.service_account_key)?;
        Ok(Some(r))
    }

    async fn put_device_config(&self, mut record: DeviceConfigRecord, actor: &str) -> Result<()> {
        record.service_account_key = self.seal(record.service_account_key.as_deref())?;
        self.inner.put_device_config(record, actor).await
    }

    async fn get_idp_config(&self) -> Result<Option<IdpConfigRecord>> {
        let Some(mut r) = self.inner.get_idp_config().await? else {
            return Ok(None);
        };
        // Both, matching the hosted wrapper exactly. The certificate is public
        // and does not need protecting, but sealing it costs nothing and the
        // two implementations disagreeing on which columns are ciphertext
        // would make a database unreadable by the other deployment.
        r.saml_cert = self.unseal(r.saml_cert)?;
        r.saml_signing_key = self.unseal(r.saml_signing_key)?;
        Ok(Some(r))
    }

    async fn put_idp_config(&self, mut record: IdpConfigRecord, actor: &str) -> Result<()> {
        record.saml_cert = self.seal(record.saml_cert.as_deref())?;
        record.saml_signing_key = self.seal(record.saml_signing_key.as_deref())?;
        self.inner.put_idp_config(record, actor).await
    }

    async fn get_ad_sync_config(&self) -> Result<Option<AdSyncConfigRecord>> {
        let Some(mut r) = self.inner.get_ad_sync_config().await? else {
            return Ok(None);
        };
        r.bind_password = self.unseal(r.bind_password)?;
        r.tls_ca_cert = self.unseal(r.tls_ca_cert)?;
        Ok(Some(r))
    }

    async fn put_ad_sync_config(&self, mut record: AdSyncConfigRecord, actor: &str) -> Result<()> {
        record.bind_password = self.seal(record.bind_password.as_deref())?;
        record.tls_ca_cert = self.seal(record.tls_ca_cert.as_deref())?;
        self.inner.put_ad_sync_config(record, actor).await
    }
}

#[cfg(test)]
mod tests;
