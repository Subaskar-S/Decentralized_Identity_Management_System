//! Cryptographic utilities for identity management

use anyhow::Result;
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use schnorrkel::{Keypair, PublicKey, SecretKey, Signature};
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::GroupEncoding;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crate::error::IdentityError;
use std::collections::HashMap;

/// Key types supported by the system
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    Ed25519,
    Secp256k1,
    Bls12381G1,
    Bls12381G2,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "Ed25519VerificationKey2020"),
            KeyType::Secp256k1 => write!(f, "EcdsaSecp256k1VerificationKey2019"),
            KeyType::Bls12381G1 => write!(f, "Bls12381G1Key2020"),
            KeyType::Bls12381G2 => write!(f, "Bls12381G2Key2020"),
        }
    }
}

/// Cryptographic key pair
#[derive(Debug, Clone)]
pub struct CryptoKeyPair {
    pub key_type: KeyType,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Generate a cryptographic hash of data
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Generate a hash of JSON-serializable data
pub fn hash_json<T: serde::Serialize>(data: &T) -> Result<Vec<u8>, IdentityError> {
    let json = serde_json::to_vec(data)?;
    Ok(hash_data(&json))
}

/// Generate an Ed25519 keypair using Schnorrkel
pub fn generate_ed25519_keypair() -> Result<CryptoKeyPair, IdentityError> {
    let keypair = Keypair::generate_with(&mut OsRng);

    Ok(CryptoKeyPair {
        key_type: KeyType::Ed25519,
        private_key: keypair.secret.to_bytes().to_vec(),
        public_key: keypair.public.to_bytes().to_vec(),
    })
}

/// Generate a BLS12-381 G1 keypair
pub fn generate_bls12381_g1_keypair() -> Result<CryptoKeyPair, IdentityError> {
    let private_key = Scalar::random(&mut OsRng);
    let public_key = G1Projective::generator() * private_key;

    Ok(CryptoKeyPair {
        key_type: KeyType::Bls12381G1,
        private_key: private_key.to_bytes().to_vec(),
        public_key: public_key.to_bytes().as_ref().to_vec(),
    })
}

/// Generate a BLS12-381 G2 keypair
pub fn generate_bls12381_g2_keypair() -> Result<CryptoKeyPair, IdentityError> {
    let private_key = Scalar::random(&mut OsRng);
    let public_key = G2Projective::generator() * private_key;

    Ok(CryptoKeyPair {
        key_type: KeyType::Bls12381G2,
        private_key: private_key.to_bytes().to_vec(),
        public_key: public_key.to_bytes().as_ref().to_vec(),
    })
}

/// Generate a keypair of the specified type
pub fn generate_keypair(key_type: KeyType) -> Result<CryptoKeyPair, IdentityError> {
    match key_type {
        KeyType::Ed25519 => generate_ed25519_keypair(),
        KeyType::Bls12381G1 => generate_bls12381_g1_keypair(),
        KeyType::Bls12381G2 => generate_bls12381_g2_keypair(),
        KeyType::Secp256k1 => Err(IdentityError::CryptoError("Secp256k1 not implemented yet".to_string())),
    }
}

/// Sign data with Ed25519 key
pub fn sign_ed25519(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let secret = SecretKey::from_bytes(private_key)
        .map_err(|e| IdentityError::CryptoError(format!("Invalid private key: {}", e)))?;

    let keypair = Keypair::from(secret);
    let signature = keypair.sign_simple(b"", data);

    Ok(signature.to_bytes().to_vec())
}

/// Verify Ed25519 signature
pub fn verify_ed25519(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, IdentityError> {
    let public = PublicKey::from_bytes(public_key)
        .map_err(|e| IdentityError::CryptoError(format!("Invalid public key: {}", e)))?;

    let sig = Signature::from_bytes(signature)
        .map_err(|e| IdentityError::CryptoError(format!("Invalid signature: {}", e)))?;

    Ok(public.verify_simple(b"", data, &sig).is_ok())
}

/// Convert public key to multibase format
pub fn public_key_to_multibase(public_key: &[u8], key_type: &KeyType) -> String {
    // This is a simplified implementation
    // In practice, you'd use proper multibase encoding with the correct prefixes
    match key_type {
        KeyType::Ed25519 => format!("z{}", URL_SAFE_NO_PAD.encode(public_key)),
        KeyType::Bls12381G1 => format!("z{}", URL_SAFE_NO_PAD.encode(public_key)),
        KeyType::Bls12381G2 => format!("z{}", URL_SAFE_NO_PAD.encode(public_key)),
        KeyType::Secp256k1 => format!("z{}", URL_SAFE_NO_PAD.encode(public_key)),
    }
}

/// Create a JWK (JSON Web Key) representation
pub fn public_key_to_jwk(public_key: &[u8], key_type: &KeyType) -> HashMap<String, serde_json::Value> {
    let mut jwk = HashMap::new();

    match key_type {
        KeyType::Ed25519 => {
            jwk.insert("kty".to_string(), serde_json::Value::String("OKP".to_string()));
            jwk.insert("crv".to_string(), serde_json::Value::String("Ed25519".to_string()));
            jwk.insert("x".to_string(), serde_json::Value::String(
                URL_SAFE_NO_PAD.encode(public_key)
            ));
        }
        _ => {
            // Simplified for other key types
            jwk.insert("kty".to_string(), serde_json::Value::String("EC".to_string()));
            jwk.insert("x".to_string(), serde_json::Value::String(
                URL_SAFE_NO_PAD.encode(public_key)
            ));
        }
    }

    jwk
}
