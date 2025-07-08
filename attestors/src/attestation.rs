//! Attestation logic for multiparty credential verification

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use identity_core::VerifiableCredential;
use crate::threshold::{ThresholdScheme, KeyShare, PartialSignature, ThresholdSignature, ThresholdPublicKey};
use crate::verifier::Verifier;
use crate::error::AttestorError;

/// Attestation request for a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub id: String,
    pub credential: VerifiableCredential,
    pub required_attestors: Vec<String>,
    pub threshold: usize,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Individual attestation from a verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub id: String,
    pub request_id: String,
    pub attestor_id: String,
    pub attestor_did: String,
    pub credential_id: String,
    pub status: AttestationStatus,
    pub partial_signature: Option<PartialSignature>,
    pub attestation_data: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub verified_claims: Vec<String>,
}

/// Status of an attestation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttestationStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// Complete attestation result with threshold signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    pub request_id: String,
    pub credential_id: String,
    pub threshold_signature: Option<ThresholdSignature>,
    pub participating_attestors: Vec<String>,
    pub status: AttestationResultStatus,
    pub created_at: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Status of the overall attestation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttestationResultStatus {
    InProgress,
    Completed,
    Failed,
    Expired,
}

/// Attestation manager for coordinating multiparty attestations
pub struct AttestationManager {
    pub threshold_scheme: ThresholdScheme,
    pub verifiers: HashMap<String, Verifier>,
    pub key_shares: HashMap<String, KeyShare>,
    pub threshold_public_key: ThresholdPublicKey,
    pub pending_requests: HashMap<String, AttestationRequest>,
    pub attestations: HashMap<String, Vec<Attestation>>,
}

impl AttestationRequest {
    /// Create a new attestation request
    pub fn new(
        credential: VerifiableCredential,
        required_attestors: Vec<String>,
        threshold: usize,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            credential,
            required_attestors,
            threshold,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)), // 24 hour expiry
        }
    }

    /// Check if the request has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Validate the attestation request
    pub fn validate(&self) -> Result<(), AttestorError> {
        if self.threshold == 0 || self.threshold > self.required_attestors.len() {
            return Err(AttestorError::ThresholdNotMet(
                "Invalid threshold configuration".to_string()
            ));
        }

        if self.is_expired() {
            return Err(AttestorError::InvalidSignature("Request has expired".to_string()));
        }

        // Validate the credential
        self.credential.validate()
            .map_err(|e| AttestorError::InvalidSignature(format!("Invalid credential: {}", e)))?;

        Ok(())
    }
}

impl Attestation {
    /// Create a new attestation
    pub fn new(
        request_id: String,
        attestor_id: String,
        attestor_did: String,
        credential_id: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            request_id,
            attestor_id,
            attestor_did,
            credential_id,
            status: AttestationStatus::Pending,
            partial_signature: None,
            attestation_data: HashMap::new(),
            created_at: Utc::now(),
            verified_claims: Vec::new(),
        }
    }

    /// Approve the attestation with a partial signature
    pub fn approve(&mut self, partial_signature: PartialSignature, verified_claims: Vec<String>) {
        self.status = AttestationStatus::Approved;
        self.partial_signature = Some(partial_signature);
        self.verified_claims = verified_claims;
    }

    /// Reject the attestation
    pub fn reject(&mut self, reason: String) {
        self.status = AttestationStatus::Rejected;
        self.attestation_data.insert("rejection_reason".to_string(), serde_json::Value::String(reason));
    }

    /// Add metadata to the attestation
    pub fn add_metadata(&mut self, key: String, value: serde_json::Value) {
        self.attestation_data.insert(key, value);
    }
}

impl AttestationManager {
    /// Create a new attestation manager
    pub fn new(
        threshold: usize,
        total_parties: usize,
        verifiers: Vec<Verifier>,
    ) -> Result<Self, AttestorError> {
        let threshold_scheme = ThresholdScheme::new(threshold, total_parties)?;
        let (key_shares, threshold_public_key) = threshold_scheme.generate_key_shares()?;

        let mut verifier_map = HashMap::new();
        let mut key_share_map = HashMap::new();

        for (i, verifier) in verifiers.into_iter().enumerate() {
            if i < key_shares.len() {
                key_share_map.insert(verifier.id.clone(), key_shares[i].clone());
            }
            verifier_map.insert(verifier.id.clone(), verifier);
        }

        Ok(Self {
            threshold_scheme,
            verifiers: verifier_map,
            key_shares: key_share_map,
            threshold_public_key,
            pending_requests: HashMap::new(),
            attestations: HashMap::new(),
        })
    }

    /// Submit a new attestation request
    pub fn submit_request(&mut self, request: AttestationRequest) -> Result<String, AttestorError> {
        request.validate()?;

        let request_id = request.id.clone();
        self.pending_requests.insert(request_id.clone(), request);
        self.attestations.insert(request_id.clone(), Vec::new());

        Ok(request_id)
    }

    /// Process an attestation from a verifier
    pub fn process_attestation(
        &mut self,
        request_id: &str,
        attestor_id: &str,
        approved: bool,
        verified_claims: Vec<String>,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Result<(), AttestorError> {
        let request = self.pending_requests.get(request_id)
            .ok_or_else(|| AttestorError::InvalidSignature("Request not found".to_string()))?;

        if request.is_expired() {
            return Err(AttestorError::InvalidSignature("Request has expired".to_string()));
        }

        let verifier = self.verifiers.get(attestor_id)
            .ok_or_else(|| AttestorError::InvalidSignature("Verifier not found".to_string()))?;

        let key_share = self.key_shares.get(attestor_id)
            .ok_or_else(|| AttestorError::InvalidSignature("Key share not found".to_string()))?;

        let mut attestation = Attestation::new(
            request_id.to_string(),
            attestor_id.to_string(),
            verifier.did.clone(),
            request.credential.id.clone(),
        );

        // Add metadata
        for (key, value) in metadata {
            attestation.add_metadata(key, value);
        }

        if approved {
            // Create partial signature
            let credential_bytes = serde_json::to_vec(&request.credential)
                .map_err(|e| AttestorError::InvalidSignature(format!("Serialization error: {}", e)))?;

            let partial_signature = self.threshold_scheme.partial_sign(&credential_bytes, key_share)?;
            attestation.approve(partial_signature, verified_claims);
        } else {
            attestation.reject("Attestor rejected the credential".to_string());
        }

        // Add attestation to the list
        self.attestations.get_mut(request_id).unwrap().push(attestation);

        Ok(())
    }

    /// Check if threshold is met and combine signatures
    pub fn try_complete_attestation(&mut self, request_id: &str) -> Result<Option<AttestationResult>, AttestorError> {
        let request = self.pending_requests.get(request_id)
            .ok_or_else(|| AttestorError::InvalidSignature("Request not found".to_string()))?;

        let attestations = self.attestations.get(request_id).unwrap();

        let approved_attestations: Vec<_> = attestations.iter()
            .filter(|a| a.status == AttestationStatus::Approved)
            .collect();

        if approved_attestations.len() >= request.threshold {
            // Collect partial signatures
            let partial_signatures: Vec<_> = approved_attestations.iter()
                .filter_map(|a| a.partial_signature.as_ref())
                .cloned()
                .collect();

            // Combine signatures
            let threshold_signature = self.threshold_scheme.combine_signatures(&partial_signatures)?;

            let participating_attestors: Vec<String> = approved_attestations.iter()
                .map(|a| a.attestor_id.clone())
                .collect();

            let mut metadata = HashMap::new();
            metadata.insert("threshold_met".to_string(), serde_json::Value::Bool(true));
            metadata.insert("total_attestations".to_string(), serde_json::Value::Number(attestations.len().into()));

            let result = AttestationResult {
                request_id: request_id.to_string(),
                credential_id: request.credential.id.clone(),
                threshold_signature: Some(threshold_signature),
                participating_attestors,
                status: AttestationResultStatus::Completed,
                created_at: Utc::now(),
                metadata,
            };

            // Remove completed request
            self.pending_requests.remove(request_id);

            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Get attestation status
    pub fn get_attestation_status(&self, request_id: &str) -> Option<(usize, usize)> {
        self.attestations.get(request_id).map(|attestations| {
            let approved = attestations.iter()
                .filter(|a| a.status == AttestationStatus::Approved)
                .count();
            (approved, attestations.len())
        })
    }

    /// Verify a completed attestation result
    pub fn verify_attestation_result(
        &self,
        result: &AttestationResult,
        credential: &VerifiableCredential,
    ) -> Result<bool, AttestorError> {
        if let Some(signature) = &result.threshold_signature {
            let credential_bytes = serde_json::to_vec(credential)
                .map_err(|e| AttestorError::InvalidSignature(format!("Serialization error: {}", e)))?;

            self.threshold_scheme.verify_signature(
                &credential_bytes,
                signature,
                &self.threshold_public_key,
            )
        } else {
            Ok(false)
        }
    }
}
