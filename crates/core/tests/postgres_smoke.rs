//! Postgres smoke test using testcontainers. Marked `#[ignore]` because it
//! requires a working Docker daemon — run with `cargo test -- --ignored`.
//!
//! Spins up a Postgres container, creates two schemas (`tenant_a`, `tenant_b`),
//! runs migrations into each, inserts a user into A, asserts B sees zero.
//! This validates schema-level isolation for the OSS Postgres path.

use chalk_core::config::is_valid_pg_schema;
use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::{OrgRepository, UserRepository};
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::sync::UserFilter;
use chalk_core::models::user::User;
use chrono::Utc;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

fn sample_org() -> Org {
    Org {
        sourced_id: "org-1".into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        name: "Test School".into(),
        org_type: OrgType::School,
        identifier: None,
        parent: None,
        children: vec![],
    }
}

fn sample_user(id: &str, username: &str) -> User {
    User {
        sourced_id: id.into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        username: username.into(),
        enabled_user: true,
        given_name: "Test".into(),
        family_name: "User".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: None,
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec!["org-1".into()],
        user_ids: vec![],
        grades: vec!["09".into()],
    }
}

#[tokio::test]
#[ignore = "requires Docker; run with `cargo test -- --ignored`"]
async fn schema_isolation_smoke() {
    assert!(is_valid_pg_schema("tenant_a"));

    let container = Postgres::default()
        .start()
        .await
        .expect("postgres container start");
    let host_port = container.get_host_port_ipv4(5432).await.expect("host port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres");

    // Set up two pools, one per schema.
    let pool_a = DatabasePool::new_postgres(&url, "tenant_a")
        .await
        .expect("pool a");
    pool_a
        .run_migrations_postgres("tenant_a")
        .await
        .expect("migrate a");

    let pool_b = DatabasePool::new_postgres(&url, "tenant_b")
        .await
        .expect("pool b");
    pool_b
        .run_migrations_postgres("tenant_b")
        .await
        .expect("migrate b");

    let repo_a = match pool_a {
        DatabasePool::Postgres(p) => PostgresRepository::new(p, "tenant_a".into()),
        _ => unreachable!(),
    };
    let repo_b = match pool_b {
        DatabasePool::Postgres(p) => PostgresRepository::new(p, "tenant_b".into()),
        _ => unreachable!(),
    };

    // Insert org + user into tenant_a only.
    repo_a
        .upsert_org(&sample_org())
        .await
        .expect("upsert org a");
    repo_a
        .upsert_user(&sample_user("u-1", "alice"))
        .await
        .expect("upsert user a");

    // tenant_a should see one user.
    let a_users = repo_a
        .list_users(&UserFilter::default())
        .await
        .expect("list a");
    assert_eq!(a_users.len(), 1);
    assert_eq!(a_users[0].sourced_id, "u-1");

    // tenant_b should see zero users — schema isolation.
    let b_users = repo_b
        .list_users(&UserFilter::default())
        .await
        .expect("list b");
    assert_eq!(b_users.len(), 0);

    // Migrations should be idempotent.
    let pool_a2 = DatabasePool::new_postgres(&url, "tenant_a")
        .await
        .expect("pool a re-open");
    pool_a2
        .run_migrations_postgres("tenant_a")
        .await
        .expect("migrate a again");
}

/// Spawns 4 concurrent migration runs against the same fresh schema and asserts
/// that the per-schema advisory lock prevents duplicate `_meta_schema_migrations`
/// rows. Without the lock, two callers can both pass the "already applied" check
/// before either inserts the tracking row, leading to races and (with PRIMARY
/// KEY) errors. Ignored because it requires Docker.
#[tokio::test]
#[ignore = "requires Docker; run with `cargo test -- --ignored`"]
async fn concurrent_migrations_serialize() {
    let container = Postgres::default()
        .start()
        .await
        .expect("postgres container start");
    let host_port = container.get_host_port_ipv4(5432).await.expect("host port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres");

    let schema = "tenant_test";
    assert!(is_valid_pg_schema(schema));

    // Run 4 concurrent migration tasks against the same fresh schema. We use
    // `futures::future::join_all` rather than `tokio::spawn` because the sqlx
    // pool's HRTB-bound futures don't satisfy the `'static + Send` bound that
    // `tokio::spawn` requires when borrowing `&str` arguments.
    async fn migrate_once(url: String, schema: String) -> chalk_core::error::Result<()> {
        let pool = DatabasePool::new_postgres(&url, &schema).await?;
        pool.run_migrations_postgres(&schema).await
    }
    let tasks: Vec<_> = (0..4)
        .map(|_| migrate_once(url.clone(), schema.to_string()))
        .collect();
    let results = futures_util::future::join_all(tasks).await;
    for r in results {
        r.expect("migration succeeds");
    }

    // Verify no duplicate rows landed in the tracking table.
    let pool = DatabasePool::new_postgres(&url, schema)
        .await
        .expect("verify pool");
    let pg = match &pool {
        DatabasePool::Postgres(p) => p,
        _ => unreachable!(),
    };
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT version, COUNT(*)::bigint FROM _meta_schema_migrations \
         GROUP BY version HAVING COUNT(*) > 1",
    )
    .fetch_all(pg)
    .await
    .expect("query duplicates");
    assert!(
        rows.is_empty(),
        "expected no duplicate _meta_schema_migrations rows, got {rows:?}"
    );

    // Sanity: at least one migration was applied.
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM _meta_schema_migrations")
        .fetch_one(pg)
        .await
        .expect("count rows");
    assert!(total.0 > 0, "expected migrations to have been applied");
}
