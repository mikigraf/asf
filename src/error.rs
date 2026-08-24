use thiserror::Error;

/// Errors that can be safely classified at ASF boundaries.
#[derive(Debug, Error)]
pub enum Error {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("invalid state transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("authentication failed")]
    Unauthenticated,
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("cryptographic verification failed: {0}")]
    Crypto(String),
    #[error("external system unavailable: {0}")]
    ExternalUnavailable(String),
    #[error("ambiguous external effect: {0}")]
    AmbiguousEffect(String),
    #[error("persistence error: {0}")]
    Persistence(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
