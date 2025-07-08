//! Error types for attestors

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestorError {
    #[error("Threshold not met: {0}")]
    ThresholdNotMet(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Attestation error: {0}")]
    AttestationError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Identity error: {0}")]
    IdentityError(#[from] identity_core::IdentityError),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}
