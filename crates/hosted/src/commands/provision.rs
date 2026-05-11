//! `provision` subcommand — create a new tenant.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use chalk_core::config::is_valid_pg_schema;
use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::ChalkRepository;
use chalk_core::db::DatabasePool;

use crate::admin::{self, BootstrapResult};
use crate::keys::{self, MasterKey};
use crate::meta;
use crate::tenant::{TenantRegistry, TenantStatus};
use crate::{is_valid_slug, schema_for_slug};

#[derive(Debug, Clone)]
pub struct ProvisionArgs {
    pub slug: String,
    pub admin_email: String,
    pub display_name: String,
    pub admin_name: Option<String>,
    pub postgres_url: String,
}

/// Outcome of `activate_tenant`: returned to callers (CLI, signup verify) so
/// they can hand the user the reset token / surface it in JSON output.
pub struct ActivationOutcome {
    pub slug: String,
    pub db_schema: String,
    pub admin: BootstrapResult,
}

pub async fn run(args: ProvisionArgs) -> Result<()> {
    let master_key = master_key_from_env()?;
    let outcome = activate_tenant(
        &args.postgres_url,
        &args.slug,
        &args.display_name,
        &args.admin_email,
        args.admin_name.as_deref().unwrap_or("Admin"),
        &master_key,
    )
    .await?;

    let out = serde_json::json!({
        "slug": outcome.slug,
        "schema": outcome.db_schema,
        "status": TenantStatus::Active.as_str(),
        "admin_user_id": outcome.admin.user_sourced_id,
        "reset_token": outcome.admin.reset_token,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Read `MASTER_ENCRYPTION_KEY` from env. Used by the CLI provision path so
/// manual provisions also seal keys.
fn master_key_from_env() -> Result<MasterKey> {
    let raw = std::env::var("MASTER_ENCRYPTION_KEY")
        .map_err(|_| anyhow!("MASTER_ENCRYPTION_KEY env var must be set to provision a tenant"))?;
    MasterKey::from_base64(&raw)
}

/// Idempotent activation pipeline shared by the CLI and the signup verify
/// callback.
///
/// - Validates the slug.
/// - Creates (or resumes) the `_meta.tenants` row.
/// - Runs OSS migrations against the tenant schema.
/// - Generates per-tenant SAML + OIDC key material, seals it with the master
///   key, and writes it to `_meta.tenants`.
/// - Marks the tenant `active`.
/// - Bootstraps the admin user and returns the one-time reset token.
pub async fn activate_tenant(
    postgres_url: &str,
    slug: &str,
    display_name: &str,
    admin_email: &str,
    admin_name: &str,
    master_key: &MasterKey,
) -> Result<ActivationOutcome> {
    if !is_valid_slug(slug) {
        return Err(anyhow!(
            "invalid slug `{slug}`: must match ^[a-z][a-z0-9-]{{2,30}}$ and not be reserved"
        ));
    }
    let db_schema = schema_for_slug(slug);
    if !is_valid_pg_schema(&db_schema) {
        return Err(anyhow!("computed schema name `{db_schema}` is invalid"));
    }

    let meta_pool = meta::connect_meta(postgres_url).await?;

    let registry = TenantRegistry::new(meta_pool);

    if let Some(existing) = registry.get(slug).await? {
        match existing.status {
            TenantStatus::Active => {
                return Err(anyhow!("tenant `{slug}` already exists and is active"));
            }
            TenantStatus::Suspended => {
                return Err(anyhow!(
                    "tenant `{slug}` exists but is suspended; resolve manually"
                ));
            }
            TenantStatus::Provisioning => {
                tracing::warn!("resuming provisioning of tenant `{slug}`");
            }
        }
    } else {
        registry.create(slug, display_name, admin_email).await?;
    }

    // Run OSS migrations and prepare the tenant repository.
    let pool = DatabasePool::new_postgres(postgres_url, &db_schema).await?;
    pool.run_migrations_postgres(&db_schema).await?;
    let pg_pool = match pool {
        DatabasePool::Postgres(p) => p,
        _ => return Err(anyhow!("expected postgres pool")),
    };
    let repo: Arc<dyn ChalkRepository> =
        Arc::new(PostgresRepository::new(pg_pool, db_schema.clone()));

    // Generate + seal SAML + OIDC material.
    let saml_blob = keys::generate_saml_blob(slug)?;
    let sealed_saml = keys::seal(master_key, &saml_blob)?;
    let oidc_pem = keys::generate_oidc_signing_key()?;
    let sealed_oidc = keys::seal(master_key, &oidc_pem)?;
    registry
        .set_sealed_keys(slug, &sealed_saml, &sealed_oidc)
        .await?;

    registry.activate(slug).await?;

    let admin = admin::bootstrap_admin(&repo, admin_email, admin_name).await?;

    // Audit: provisioning + admin bootstrap. Both events use actor=`system`
    // since these run from the activation pipeline (CLI or signup callback).
    // Failures here are non-fatal — activation already succeeded; we just
    // log the audit-write failure so it doesn't silently disappear.
    let provisioned_meta = serde_json::json!({
        "actor": "system",
        "target": slug,
        "display_name": display_name,
        "admin_email": admin_email,
    })
    .to_string();
    if let Err(e) = repo
        .log_admin_action("tenant_provisioned", Some(&provisioned_meta), None)
        .await
    {
        tracing::warn!(
            slug = %slug,
            error = %e,
            "failed to write tenant_provisioned audit row"
        );
    }

    let bootstrapped_meta = serde_json::json!({
        "actor": "system",
        "target": admin.user_sourced_id,
        "email": admin_email,
        "role": "administrator",
    })
    .to_string();
    if let Err(e) = repo
        .log_admin_action("admin_bootstrapped", Some(&bootstrapped_meta), None)
        .await
    {
        tracing::warn!(
            slug = %slug,
            error = %e,
            "failed to write admin_bootstrapped audit row"
        );
    }

    Ok(ActivationOutcome {
        slug: slug.to_string(),
        db_schema,
        admin,
    })
}
