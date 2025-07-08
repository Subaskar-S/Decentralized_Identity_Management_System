//! Credential registry for Substrate runtime

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Credential registry entry stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRegistryEntry {
    pub credential_id: String,
    pub credential_hash: String, // IPFS hash
    pub issuer_did: String,
    pub subject_did: Option<String>,
    pub schema_id: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: CredentialStatus,
    pub revocation_reason: Option<String>,
    pub attestation_count: u32,
    pub required_attestations: u32,
    pub metadata: HashMap<String, String>,
}

/// Status of a credential
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CredentialStatus {
    Pending,      // Waiting for attestations
    Active,       // Fully attested and valid
    Revoked,      // Revoked by issuer
    Expired,      // Past expiration date
    Suspended,    // Temporarily suspended
}

/// Revocation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub credential_id: String,
    pub revoked_at: DateTime<Utc>,
    pub revoked_by: String,
    pub reason: String,
    pub revocation_list_hash: Option<String>,
}

/// Credential registry for managing credentials on-chain
pub struct CredentialRegistry {
    entries: HashMap<String, CredentialRegistryEntry>,
    revocations: HashMap<String, RevocationEntry>,
    schema_registry: HashMap<String, String>, // schema_id -> schema_hash
}

impl CredentialRegistry {
    /// Create a new credential registry
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            revocations: HashMap::new(),
            schema_registry: HashMap::new(),
        }
    }

    /// Register a new credential
    pub fn register_credential(
        &mut self,
        credential_id: String,
        credential_hash: String,
        issuer_did: String,
        subject_did: Option<String>,
        schema_id: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        required_attestations: u32,
    ) -> Result<(), String> {
        if self.entries.contains_key(&credential_id) {
            return Err("Credential already exists".to_string());
        }

        let entry = CredentialRegistryEntry {
            credential_id: credential_id.clone(),
            credential_hash,
            issuer_did,
            subject_did,
            schema_id,
            issued_at: Utc::now(),
            expires_at,
            status: if required_attestations > 0 {
                CredentialStatus::Pending
            } else {
                CredentialStatus::Active
            },
            revocation_reason: None,
            attestation_count: 0,
            required_attestations,
            metadata: HashMap::new(),
        };

        self.entries.insert(credential_id, entry);
        Ok(())
    }

    /// Add attestation to a credential
    pub fn add_attestation(&mut self, credential_id: &str) -> Result<(), String> {
        let entry = self.entries.get_mut(credential_id)
            .ok_or("Credential not found")?;

        if entry.status != CredentialStatus::Pending {
            return Err("Credential is not pending attestation".to_string());
        }

        entry.attestation_count += 1;

        // Check if threshold is met
        if entry.attestation_count >= entry.required_attestations {
            entry.status = CredentialStatus::Active;
        }

        Ok(())
    }

    /// Revoke a credential
    pub fn revoke_credential(
        &mut self,
        credential_id: &str,
        revoked_by: String,
        reason: String,
    ) -> Result<(), String> {
        let entry = self.entries.get_mut(credential_id)
            .ok_or("Credential not found")?;

        if entry.status == CredentialStatus::Revoked {
            return Err("Credential already revoked".to_string());
        }

        entry.status = CredentialStatus::Revoked;
        entry.revocation_reason = Some(reason.clone());

        let revocation = RevocationEntry {
            credential_id: credential_id.to_string(),
            revoked_at: Utc::now(),
            revoked_by,
            reason,
            revocation_list_hash: None,
        };

        self.revocations.insert(credential_id.to_string(), revocation);
        Ok(())
    }

    /// Check credential status
    pub fn get_credential_status(&self, credential_id: &str) -> Option<&CredentialStatus> {
        self.entries.get(credential_id).map(|entry| {
            // Check expiration
            if let Some(expires_at) = entry.expires_at {
                if Utc::now() > expires_at {
                    return &CredentialStatus::Expired;
                }
            }
            &entry.status
        })
    }

    /// Get credential entry
    pub fn get_credential(&self, credential_id: &str) -> Option<&CredentialRegistryEntry> {
        self.entries.get(credential_id)
    }

    /// Check if credential is valid (active and not expired)
    pub fn is_valid(&self, credential_id: &str) -> bool {
        match self.get_credential_status(credential_id) {
            Some(CredentialStatus::Active) => true,
            _ => false,
        }
    }

    /// List credentials by issuer
    pub fn list_credentials_by_issuer(&self, issuer_did: &str) -> Vec<&CredentialRegistryEntry> {
        self.entries.values()
            .filter(|entry| entry.issuer_did == issuer_did)
            .collect()
    }

    /// List credentials by subject
    pub fn list_credentials_by_subject(&self, subject_did: &str) -> Vec<&CredentialRegistryEntry> {
        self.entries.values()
            .filter(|entry| entry.subject_did.as_ref().map(|s| s.as_str()) == Some(subject_did))
            .collect()
    }

    /// Register a schema
    pub fn register_schema(&mut self, schema_id: String, schema_hash: String) -> Result<(), String> {
        if self.schema_registry.contains_key(&schema_id) {
            return Err("Schema already exists".to_string());
        }

        self.schema_registry.insert(schema_id, schema_hash);
        Ok(())
    }

    /// Get schema hash
    pub fn get_schema_hash(&self, schema_id: &str) -> Option<&String> {
        self.schema_registry.get(schema_id)
    }

    /// Get revocation info
    pub fn get_revocation_info(&self, credential_id: &str) -> Option<&RevocationEntry> {
        self.revocations.get(credential_id)
    }
}

impl Default for CredentialRegistry {
    fn default() -> Self {
        Self::new()
    }
}
