//! Sealing tests.
//!
//! Run against a real SQLite repository rather than a mock: the point of this
//! wrapper is what reaches the *database*, and a mock inner repo would let a
//! bug where plaintext is stored pass unnoticed.

use super::*;

use crate::crypto;
use crate::db::sqlite::SqliteRepository;
use crate::db::DatabasePool;

async fn inner() -> Arc<SqliteRepository> {
    let pool = DatabasePool::new_sqlite_memory().await.unwrap();
    match pool {
        DatabasePool::Sqlite(p) => Arc::new(SqliteRepository::new(p)),
        DatabasePool::Postgres(_) => unreachable!("tests use sqlite memory"),
    }
}

const KEY: [u8; 32] = [7u8; 32];

fn sealed(inner: Arc<SqliteRepository>, key: [u8; 32]) -> SealingConfigRepo {
    SealingConfigRepo::new(inner, key)
}

/// The property the whole wrapper exists for: what a caller hands in comes
/// back unchanged, and what sits in the database is not it.
#[tokio::test]
async fn a_secret_round_trips_as_plaintext_but_is_stored_as_ciphertext() {
    let raw = inner().await;
    let repo = sealed(raw.clone(), KEY);

    let key_json = br#"{"type":"service_account","private_key":"-----BEGIN..."}"#.to_vec();
    repo.put_device_config(
        DeviceConfigRecord {
            enabled: true,
            admin_email: Some("admin@example.edu".into()),
            service_account_key: Some(key_json.clone()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();

    // Through the wrapper: plaintext.
    let via_wrapper = repo.get_device_config().await.unwrap().unwrap();
    assert_eq!(
        via_wrapper.service_account_key.as_deref(),
        Some(&key_json[..])
    );

    // Straight from the database: not plaintext, and long enough to carry a
    // nonce and a GCM tag.
    let stored = raw
        .get_device_config()
        .await
        .unwrap()
        .unwrap()
        .service_account_key
        .expect("a key is on file");
    assert_ne!(stored, key_json, "the database is holding plaintext");
    assert!(
        stored.len() >= key_json.len() + 28,
        "ciphertext must carry a 12-byte nonce and a 16-byte tag"
    );
    assert!(
        !stored.windows(14).any(|w| w == b"private_key\":\""),
        "no recognisable fragment of the key may survive in storage"
    );
}

/// Every secret-bearing column, not just the one the device module cares
/// about. A field added to a record but forgotten here would be written in
/// plaintext, and nothing else would notice.
#[tokio::test]
async fn every_secret_field_is_sealed_in_storage() {
    let raw = inner().await;
    let repo = sealed(raw.clone(), KEY);

    repo.put_sis_config(
        SisConfigRecord {
            powerschool_client_secret: Some(b"ps-secret".to_vec()),
            infinite_campus_client_secret: Some(b"ic-secret".to_vec()),
            skyward_client_secret: Some(b"sky-secret".to_vec()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();
    let stored = raw.get_sis_config().await.unwrap().unwrap();
    for (field, plaintext) in [
        (stored.powerschool_client_secret, &b"ps-secret"[..]),
        (stored.infinite_campus_client_secret, &b"ic-secret"[..]),
        (stored.skyward_client_secret, &b"sky-secret"[..]),
    ] {
        assert_ne!(field.as_deref(), Some(plaintext), "stored in plaintext");
    }

    repo.put_google_sync_config(
        GoogleSyncConfigRecord {
            service_account_key: Some(b"gs-key".to_vec()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();
    assert_ne!(
        raw.get_google_sync_config()
            .await
            .unwrap()
            .unwrap()
            .service_account_key
            .as_deref(),
        Some(&b"gs-key"[..])
    );

    repo.put_ad_sync_config(
        AdSyncConfigRecord {
            bind_password: Some(b"bind-pw".to_vec()),
            tls_ca_cert: Some(b"ca-cert".to_vec()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();
    let ad = raw.get_ad_sync_config().await.unwrap().unwrap();
    assert_ne!(ad.bind_password.as_deref(), Some(&b"bind-pw"[..]));
    assert_ne!(ad.tls_ca_cert.as_deref(), Some(&b"ca-cert"[..]));
}

/// A wrong master key must fail loudly. Returning `None` would render the
/// console as "Google is not set up", inviting an operator to overwrite a
/// credential that is merely unreadable — turning a recoverable restore
/// mistake into data loss.
#[tokio::test]
async fn the_wrong_master_key_errors_rather_than_reading_as_unconfigured() {
    let raw = inner().await;
    sealed(raw.clone(), KEY)
        .put_device_config(
            DeviceConfigRecord {
                service_account_key: Some(b"the real key".to_vec()),
                ..Default::default()
            },
            "admin-1",
        )
        .await
        .unwrap();

    let wrong = sealed(raw.clone(), [9u8; 32]);
    let err = wrong.get_device_config().await;
    assert!(
        err.is_err(),
        "a wrong key must not look like an empty configuration"
    );
}

/// Tampering is detected. That is what AES-GCM's tag is for, and the wrapper
/// must surface the failure rather than swallow it.
#[tokio::test]
async fn tampered_ciphertext_is_rejected() {
    let raw = inner().await;
    let repo = sealed(raw.clone(), KEY);
    repo.put_device_config(
        DeviceConfigRecord {
            service_account_key: Some(b"the real key".to_vec()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();

    // Flip one bit in the stored ciphertext.
    let mut stored = raw
        .get_device_config()
        .await
        .unwrap()
        .unwrap()
        .service_account_key
        .unwrap();
    let last = stored.len() - 1;
    stored[last] ^= 0x01;
    raw.put_device_config(
        DeviceConfigRecord {
            service_account_key: Some(stored),
            ..Default::default()
        },
        "attacker",
    )
    .await
    .unwrap();

    assert!(repo.get_device_config().await.is_err());
}

/// Empty is unset in both directions.
///
/// Sealing `b""` produces a valid non-empty ciphertext that would round-trip
/// as `Some(b"")`, and a console checking `is_some()` to decide whether a
/// credential is on file would then claim one exists.
#[tokio::test]
async fn an_empty_secret_is_treated_as_absent() {
    let raw = inner().await;
    let repo = sealed(raw.clone(), KEY);

    repo.put_device_config(
        DeviceConfigRecord {
            service_account_key: Some(Vec::new()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();

    assert_eq!(
        raw.get_device_config()
            .await
            .unwrap()
            .unwrap()
            .service_account_key,
        None,
        "an empty secret must not become a sealed empty string"
    );
    assert_eq!(
        repo.get_device_config()
            .await
            .unwrap()
            .unwrap()
            .service_account_key,
        None
    );
}

/// An empty stored cell reads as unset rather than failing the whole config.
/// It can only come from hand-written SQL, and refusing to load a district's
/// entire configuration over one stray cell is the wrong trade.
#[tokio::test]
async fn an_empty_stored_cell_reads_as_unset() {
    let raw = inner().await;
    raw.put_device_config(
        DeviceConfigRecord {
            enabled: true,
            service_account_key: Some(Vec::new()),
            ..Default::default()
        },
        "admin-1",
    )
    .await
    .unwrap();

    let via_wrapper = sealed(raw, KEY).get_device_config().await.unwrap().unwrap();
    assert_eq!(via_wrapper.service_account_key, None);
    assert!(via_wrapper.enabled, "the rest of the record still loads");
}

/// Nothing configured stays `None` through the wrapper — it must not
/// manufacture an empty record.
#[tokio::test]
async fn an_unconfigured_section_stays_none() {
    let repo = sealed(inner().await, KEY);
    assert!(repo.get_device_config().await.unwrap().is_none());
    assert!(repo.get_sis_config().await.unwrap().is_none());
    assert!(repo.get_google_sync_config().await.unwrap().is_none());
}

/// The master key is a fixed 32 bytes. A short or padded file is almost always
/// the wrong file, and truncating it silently would encrypt every secret under
/// a key nobody can reproduce.
#[test]
fn loading_a_master_key_of_the_wrong_length_is_refused() {
    let dir = tempfile::tempdir().unwrap();

    let good = dir.path().join("good.key");
    std::fs::write(&good, [3u8; 32]).unwrap();
    assert_eq!(SealingConfigRepo::load_key(&good).unwrap(), [3u8; 32]);

    for (name, bytes) in [("short.key", vec![1u8; 31]), ("long.key", vec![1u8; 33])] {
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        let err = SealingConfigRepo::load_key(&path).unwrap_err().to_string();
        assert!(err.contains("expected exactly 32"), "got: {err}");
    }

    let missing = dir.path().join("nope.key");
    assert!(SealingConfigRepo::load_key(&missing).is_err());
}

/// Sanity check on the primitive the wrapper leans on: two seals of the same
/// plaintext differ, so the nonce is not reused.
#[test]
fn sealing_the_same_secret_twice_produces_different_ciphertext() {
    let a = crypto::encrypt(&KEY, b"same secret").unwrap();
    let b = crypto::encrypt(&KEY, b"same secret").unwrap();
    assert_ne!(a, b, "a reused nonce would leak plaintext relationships");
    assert_eq!(crypto::decrypt(&KEY, &a).unwrap(), b"same secret");
    assert_eq!(crypto::decrypt(&KEY, &b).unwrap(), b"same secret");
}
