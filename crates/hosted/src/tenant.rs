//! Tenant identity types and the `_meta.tenants` registry.

use anyhow::{anyhow, Result};
use sqlx::PgPool;

use crate::schema_for_slug;

/// Sealed key material loaded from `_meta.tenants` for a given slug.
#[derive(Clone, Debug, Default)]
pub struct SealedTenantKeys {
    pub saml_keypair: Option<Vec<u8>>,
    pub oidc_signing_jwk: Option<Vec<u8>>,
}

/// Strongly-typed tenant identifier (the URL slug).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TenantId(pub String);

/// Full tenant record loaded from `_meta.tenants`.
#[derive(Clone, Debug)]
pub struct TenantRecord {
    pub slug: String,
    pub db_schema: String,
    pub status: TenantStatus,
    pub display_name: String,
    pub admin_email: String,
}

/// Lifecycle status of a tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    Suspended,
    Provisioning,
}

impl TenantStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
            TenantStatus::Provisioning => "provisioning",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "active" => TenantStatus::Active,
            "suspended" => TenantStatus::Suspended,
            "provisioning" => TenantStatus::Provisioning,
            other => {
                tracing::warn!("unknown tenant status: {other}");
                TenantStatus::Suspended
            }
        }
    }
}

/// Registry over the `_meta.tenants` table.
#[derive(Clone)]
pub struct TenantRegistry {
    meta_pool: PgPool,
}

impl TenantRegistry {
    pub fn new(meta_pool: PgPool) -> Self {
        Self { meta_pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.meta_pool
    }

    /// Fetch a tenant by slug.
    pub async fn get(&self, slug: &str) -> Result<Option<TenantRecord>> {
        let row: Option<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT slug, db_schema, status, display_name, admin_email \
             FROM _meta.tenants WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.meta_pool)
        .await?;
        Ok(row.map(
            |(slug, db_schema, status, display_name, admin_email)| TenantRecord {
                slug,
                db_schema,
                status: TenantStatus::parse(&status),
                display_name,
                admin_email,
            },
        ))
    }

    /// List all tenants whose status is `active`.
    pub async fn list_active(&self) -> Result<Vec<TenantRecord>> {
        let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT slug, db_schema, status, display_name, admin_email \
             FROM _meta.tenants WHERE status = $1 ORDER BY slug",
        )
        .bind(TenantStatus::Active.as_str())
        .fetch_all(&self.meta_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(slug, db_schema, status, display_name, admin_email)| TenantRecord {
                    slug,
                    db_schema,
                    status: TenantStatus::parse(&status),
                    display_name,
                    admin_email,
                },
            )
            .collect())
    }

    /// Create a new tenant row with `status = 'provisioning'`.
    pub async fn create(
        &self,
        slug: &str,
        display_name: &str,
        admin_email: &str,
    ) -> Result<TenantRecord> {
        let db_schema = schema_for_slug(slug);
        sqlx::query(
            "INSERT INTO _meta.tenants (slug, db_schema, status, display_name, admin_email) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(slug)
        .bind(&db_schema)
        .bind(TenantStatus::Provisioning.as_str())
        .bind(display_name)
        .bind(admin_email)
        .execute(&self.meta_pool)
        .await
        .map_err(|e| anyhow!("failed to insert tenant {slug}: {e}"))?;
        Ok(TenantRecord {
            slug: slug.to_string(),
            db_schema,
            status: TenantStatus::Provisioning,
            display_name: display_name.to_string(),
            admin_email: admin_email.to_string(),
        })
    }

    /// Mark a tenant `active`.
    pub async fn activate(&self, slug: &str) -> Result<()> {
        self.set_status(slug, TenantStatus::Active).await
    }

    /// Mark a tenant `suspended`.
    pub async fn suspend(&self, slug: &str) -> Result<()> {
        self.set_status(slug, TenantStatus::Suspended).await
    }

    async fn set_status(&self, slug: &str, status: TenantStatus) -> Result<()> {
        let res =
            sqlx::query("UPDATE _meta.tenants SET status = $1, updated_at = now() WHERE slug = $2")
                .bind(status.as_str())
                .bind(slug)
                .execute(&self.meta_pool)
                .await?;
        if res.rows_affected() == 0 {
            return Err(anyhow!("tenant not found: {slug}"));
        }
        Ok(())
    }

    /// Persist sealed SAML keypair + sealed OIDC JWK for a tenant.
    pub async fn set_sealed_keys(
        &self,
        slug: &str,
        saml_keypair: &[u8],
        oidc_signing_jwk: &[u8],
    ) -> Result<()> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let oidc_json = serde_json::json!({ "sealed": B64.encode(oidc_signing_jwk) });
        let res = sqlx::query(
            "UPDATE _meta.tenants \
             SET saml_keypair = $1, oidc_signing_jwk = $2, updated_at = now() \
             WHERE slug = $3",
        )
        .bind(saml_keypair)
        .bind(&oidc_json)
        .bind(slug)
        .execute(&self.meta_pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(anyhow!("tenant not found: {slug}"));
        }
        Ok(())
    }

    /// Load sealed SAML keypair + sealed OIDC JWK for a tenant. Either column
    /// may be null (for tenants provisioned before key sealing landed).
    pub async fn get_sealed_keys(&self, slug: &str) -> Result<SealedTenantKeys> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let row: Option<(Option<Vec<u8>>, Option<serde_json::Value>)> = sqlx::query_as(
            "SELECT saml_keypair, oidc_signing_jwk FROM _meta.tenants WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.meta_pool)
        .await?;
        let (saml, oidc_json) = match row {
            Some(r) => r,
            None => return Ok(SealedTenantKeys::default()),
        };
        let oidc = match oidc_json {
            Some(v) => v
                .get("sealed")
                .and_then(|s| s.as_str())
                .map(|s| B64.decode(s))
                .transpose()
                .map_err(|e| anyhow!("invalid oidc_signing_jwk base64: {e}"))?,
            None => None,
        };
        Ok(SealedTenantKeys {
            saml_keypair: saml,
            oidc_signing_jwk: oidc,
        })
    }

    /// Delete a tenant row from the registry. Does NOT drop the tenant schema;
    /// callers must do that separately.
    pub async fn delete(&self, slug: &str) -> Result<()> {
        let res = sqlx::query("DELETE FROM _meta.tenants WHERE slug = $1")
            .bind(slug)
            .execute(&self.meta_pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(anyhow!("tenant not found: {slug}"));
        }
        Ok(())
    }
}
