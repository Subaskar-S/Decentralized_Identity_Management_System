//! Error types for identity core

use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("Invalid credential: {0}")]
    InvalidCredential(String),

    #[error("Invalid presentation: {0}")]
    InvalidPresentation(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}
