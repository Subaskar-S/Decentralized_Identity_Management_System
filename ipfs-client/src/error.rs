//! Error types for IPFS client

use thiserror::Error;

#[derive(Error, Debug)]
pub enum IpfsError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Retrieval error: {0}")]
    RetrievalError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Network timeout: {0}")]
    TimeoutError(String),

    #[error("Content not found: {0}")]
    NotFound(String),

    #[error("Invalid content: {0}")]
    InvalidContent(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("Node unavailable: {0}")]
    NodeUnavailable(String),

    #[error("Integrity check failed: {0}")]
    IntegrityError(String),
}
