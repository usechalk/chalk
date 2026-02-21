//! Error types for the Chalk core crate.

use thiserror::Error;

/// Top-level error type for all Chalk core operations.
#[derive(Debug, Error)]
pub enum ChalkError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("sync error: {0}")]
    Sync(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("IDP error: {0}")]
    Idp(String),

    #[error("Google Sync error: {0}")]
    GoogleSync(String),

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("SAML error: {0}")]
    Saml(String),
}

/// A convenience Result alias that defaults to [`ChalkError`].
pub type Result<T> = std::result::Result<T, ChalkError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_display() {
        let err = ChalkError::Config("missing field".into());
        assert_eq!(err.to_string(), "configuration error: missing field");
    }

    #[test]
    fn io_error_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = ChalkError::from(io_err);
        assert!(matches!(err, ChalkError::Io(_)));
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn serialization_error_display() {
        let err = ChalkError::Serialization("invalid JSON".into());
        assert_eq!(err.to_string(), "serialization error: invalid JSON");
    }

    #[test]
    fn sync_error_display() {
        let err = ChalkError::Sync("timeout".into());
        assert_eq!(err.to_string(), "sync error: timeout");
    }

    #[test]
    fn result_alias_works() {
        let ok: Result<i32> = Ok(42);
        assert!(ok.is_ok());

        let err: Result<i32> = Err(ChalkError::Config("bad".into()));
        assert!(err.is_err());
    }
}
