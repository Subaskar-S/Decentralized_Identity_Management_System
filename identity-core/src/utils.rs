//! Utility functions for identity management

use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::error::IdentityError;
use crate::crypto::{CryptoKeyPair, KeyType, generate_keypair};
use crate::did::{DidDocument, VerificationMethod, PublicKeyFormat, VerificationRelationship};

/// Generate a unique identifier
pub fn generate_id() -> String {
    Uuid::new_v4().to_string()
}

/// Generate a DID with the specified method
pub fn generate_did(method: &str) -> String {
    format!("did:{}:{}", method, generate_id())
}

/// Generate a DID with a specific identifier
pub fn generate_did_with_id(method: &str, id: &str) -> String {
    format!("did:{}:{}", method, id)
}

/// Parse a DID into its components
pub fn parse_did(did: &str) -> Result<(String, String, String), IdentityError> {
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 {
        return Err(IdentityError::InvalidDid("DID must have at least 3 parts".to_string()));
    }

    if parts[0] != "did" {
        return Err(IdentityError::InvalidDid("DID must start with 'did:'".to_string()));
    }

    let method = parts[1].to_string();
    let method_specific_id = parts[2..].join(":");

    Ok(("did".to_string(), method, method_specific_id))
}

/// Create a basic DID document with a single verification method
pub fn create_basic_did_document(
    method: &str,
    key_type: KeyType,
) -> Result<(DidDocument, CryptoKeyPair), IdentityError> {
    let keypair = generate_keypair(key_type.clone())?;
    let did = generate_did(method);
    let mut did_doc = DidDocument::new(did.clone());

    // Create verification method
    let vm_id = format!("{}#key-1", did);
    let verification_method = VerificationMethod {
        id: vm_id.clone(),
        method_type: key_type.to_string(),
        controller: did.clone(),
        public_key: PublicKeyFormat::Multibase {
            public_key_multibase: crate::crypto::public_key_to_multibase(&keypair.public_key, &key_type),
        },
    };

    did_doc.add_verification_method(verification_method);
    did_doc.add_authentication(VerificationRelationship::Reference(vm_id.clone()));

    Ok((did_doc, keypair))
}

/// Validate a timestamp is not in the future
pub fn validate_timestamp(timestamp: DateTime<Utc>) -> Result<(), IdentityError> {
    if timestamp > Utc::now() {
        return Err(IdentityError::InvalidCredential("Timestamp cannot be in the future".to_string()));
    }
    Ok(())
}

/// Generate a credential ID
pub fn generate_credential_id() -> String {
    format!("urn:uuid:{}", generate_id())
}

/// Generate a presentation ID
pub fn generate_presentation_id() -> String {
    format!("urn:uuid:{}", generate_id())
}

/// Normalize a JSON object for consistent hashing
pub fn normalize_json(value: &serde_json::Value) -> Result<String, IdentityError> {
    // This is a simplified normalization
    // In production, you'd use JSON-LD canonicalization
    let normalized = serde_json::to_string(value)?;
    Ok(normalized)
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, IdentityError> {
    hex::decode(hex).map_err(|e| IdentityError::EncodingError(format!("Invalid hex: {}", e)))
}

/// Validate a URL
pub fn validate_url(url: &str) -> Result<(), IdentityError> {
    url::Url::parse(url)
        .map_err(|e| IdentityError::InvalidDid(format!("Invalid URL: {}", e)))?;
    Ok(())
}

/// Generate a random nonce
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let nonce: u64 = rng.gen();
    format!("{:x}", nonce)
}
