//! Repository parity tests: same operations against SQLite (in-memory) and
//! Postgres (testcontainer) producing matching results. `#[ignore]` because
//! the Postgres half needs Docker — run with `cargo test -- --ignored`.

use chalk_core::db::postgres::PostgresRepository;
use chalk_core::db::repository::ChalkRepository;
use chalk_core::db::sqlite::SqliteRepository;
use chalk_core::db::DatabasePool;
use chalk_core::models::common::{OrgType, RoleType, Status};
use chalk_core::models::org::Org;
use chalk_core::models::sync::UserFilter;
use chalk_core::models::user::User;
use chrono::Utc;
use std::sync::Arc;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

fn sample_org() -> Org {
    Org {
        sourced_id: "org-1".into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        name: "Parity School".into(),
        org_type: OrgType::School,
        identifier: Some("PS-1".into()),
        parent: None,
        children: vec![],
    }
}

fn sample_user() -> User {
    User {
        sourced_id: "u-1".into(),
        status: Status::Active,
        date_last_modified: Utc::now(),
        metadata: None,
        username: "alice".into(),
        enabled_user: true,
        given_name: "Alice".into(),
        family_name: "Anderson".into(),
        middle_name: None,
        role: RoleType::Student,
        identifier: None,
        email: Some("alice@example.com".into()),
        sms: None,
        phone: None,
        agents: vec![],
        orgs: vec!["org-1".into()],
        user_ids: vec![],
        grades: vec!["09".into()],
    }
}

async fn exercise(repo: Arc<dyn ChalkRepository>) -> (Org, User, usize, i64) {
    repo.upsert_org(&sample_org()).await.unwrap();
    repo.upsert_user(&sample_user()).await.unwrap();

    let org = repo.get_org("org-1").await.unwrap().unwrap();
    let user = repo.get_user("u-1").await.unwrap().unwrap();
    let users = repo.list_users(&UserFilter::default()).await.unwrap();
    let audit_id = repo
        .log_admin_action("test.action", Some("parity"), Some("127.0.0.1"))
        .await
        .unwrap();

    (org, user, users.len(), audit_id)
}

#[tokio::test]
#[ignore = "requires Docker; run with `cargo test -- --ignored`"]
async fn parity_sqlite_vs_postgres() {
    // SQLite (in-memory)
    let sqlite_pool = DatabasePool::new_sqlite_memory().await.unwrap();
    let sqlite_repo: Arc<dyn ChalkRepository> = match sqlite_pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        _ => unreachable!(),
    };

    // Postgres (testcontainer)
    let container = Postgres::default().start().await.expect("pg container");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pg_pool = DatabasePool::new_postgres(&url, "parity")
        .await
        .expect("pg pool");
    pg_pool
        .run_migrations_postgres("parity")
        .await
        .expect("pg migrations");
    let pg_repo: Arc<dyn ChalkRepository> = match pg_pool {
        DatabasePool::Postgres(p) => Arc::new(PostgresRepository::new(p, "parity".into())),
        _ => unreachable!(),
    };

    let (s_org, s_user, s_count, _s_audit) = exercise(sqlite_repo).await;
    let (p_org, p_user, p_count, _p_audit) = exercise(pg_repo).await;

    assert_eq!(s_org.sourced_id, p_org.sourced_id);
    assert_eq!(s_org.name, p_org.name);
    assert_eq!(s_org.org_type, p_org.org_type);
    assert_eq!(s_org.identifier, p_org.identifier);

    assert_eq!(s_user.sourced_id, p_user.sourced_id);
    assert_eq!(s_user.username, p_user.username);
    assert_eq!(s_user.given_name, p_user.given_name);
    assert_eq!(s_user.family_name, p_user.family_name);
    assert_eq!(s_user.role, p_user.role);
    assert_eq!(s_user.email, p_user.email);
    assert_eq!(s_user.orgs, p_user.orgs);
    assert_eq!(s_user.grades, p_user.grades);

    assert_eq!(s_count, 1);
    assert_eq!(p_count, 1);
}
