//! DID registry for Substrate runtime

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// DID registry entry stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRegistryEntry {
    pub did: String,
    pub document_hash: String, // IPFS hash
    pub controller: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: DidStatus,
    pub verification_methods: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Status of a DID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DidStatus {
    Active,
    Deactivated,
    Revoked,
}

/// DID registry for managing DIDs on-chain
pub struct DidRegistry {
    entries: HashMap<String, DidRegistryEntry>,
}

impl DidRegistry {
    /// Create a new DID registry
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Register a new DID
    pub fn register_did(
        &mut self,
        did: String,
        document_hash: String,
        controller: String,
        verification_methods: Vec<String>,
    ) -> Result<(), String> {
        if self.entries.contains_key(&did) {
            return Err("DID already exists".to_string());
        }

        let entry = DidRegistryEntry {
            did: did.clone(),
            document_hash,
            controller,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            status: DidStatus::Active,
            verification_methods,
            metadata: HashMap::new(),
        };

        self.entries.insert(did, entry);
        Ok(())
    }

    /// Update DID document hash
    pub fn update_did_document(
        &mut self,
        did: &str,
        new_document_hash: String,
        controller: &str,
    ) -> Result<(), String> {
        let entry = self.entries.get_mut(did)
            .ok_or("DID not found")?;

        if entry.controller != controller {
            return Err("Unauthorized: not the controller".to_string());
        }

        if entry.status != DidStatus::Active {
            return Err("DID is not active".to_string());
        }

        entry.document_hash = new_document_hash;
        entry.updated_at = Utc::now();
        Ok(())
    }

    /// Deactivate a DID
    pub fn deactivate_did(&mut self, did: &str, controller: &str) -> Result<(), String> {
        let entry = self.entries.get_mut(did)
            .ok_or("DID not found")?;

        if entry.controller != controller {
            return Err("Unauthorized: not the controller".to_string());
        }

        entry.status = DidStatus::Deactivated;
        entry.updated_at = Utc::now();
        Ok(())
    }

    /// Get DID entry
    pub fn get_did(&self, did: &str) -> Option<&DidRegistryEntry> {
        self.entries.get(did)
    }

    /// Check if DID exists and is active
    pub fn is_active(&self, did: &str) -> bool {
        self.entries.get(did)
            .map(|entry| entry.status == DidStatus::Active)
            .unwrap_or(false)
    }

    /// List all DIDs for a controller
    pub fn list_dids_by_controller(&self, controller: &str) -> Vec<&DidRegistryEntry> {
        self.entries.values()
            .filter(|entry| entry.controller == controller)
            .collect()
    }
}

impl Default for DidRegistry {
    fn default() -> Self {
        Self::new()
    }
}
