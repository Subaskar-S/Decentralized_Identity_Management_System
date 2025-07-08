//! Verifier implementation for attestation parties

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use identity_core::{VerifiableCredential, DidDocument};
use crate::error::AttestorError;

/// Verifier entity that can participate in attestations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    pub id: String,
    pub did: String,
    pub name: String,
    pub organization: Option<String>,
    pub public_key: Vec<u8>,
    pub verification_methods: Vec<String>,
    pub capabilities: Vec<VerificationCapability>,
    pub reputation_score: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of verification capabilities a verifier can have
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationCapability {
    KycVerification,
    AgeVerification,
    EducationVerification,
    EmploymentVerification,
    IdentityVerification,
    AddressVerification,
    Custom(String),
}

/// Verification criteria for specific credential types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCriteria {
    pub credential_type: String,
    pub required_fields: Vec<String>,
    pub validation_rules: HashMap<String, serde_json::Value>,
    pub minimum_evidence_level: EvidenceLevel,
}

/// Evidence level for verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum EvidenceLevel {
    Low = 1,
    Medium = 2,
    High = 3,
    VeryHigh = 4,
}

/// Verification result from a verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verifier_id: String,
    pub credential_id: String,
    pub verified_claims: Vec<String>,
    pub evidence_level: EvidenceLevel,
    pub confidence_score: f64,
    pub verification_method: String,
    pub timestamp: DateTime<Utc>,
    pub notes: Option<String>,
    pub supporting_documents: Vec<String>,
}

impl Verifier {
    /// Create a new verifier
    pub fn new(
        id: String,
        did: String,
        name: String,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            id,
            did,
            name,
            organization: None,
            public_key,
            verification_methods: Vec::new(),
            capabilities: Vec::new(),
            reputation_score: 0.0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Add a verification capability
    pub fn add_capability(&mut self, capability: VerificationCapability) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
            self.updated_at = Utc::now();
        }
    }

    /// Check if verifier has a specific capability
    pub fn has_capability(&self, capability: &VerificationCapability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Set organization information
    pub fn set_organization(&mut self, organization: String) {
        self.organization = Some(organization);
        self.updated_at = Utc::now();
    }

    /// Update reputation score
    pub fn update_reputation(&mut self, score: f64) {
        self.reputation_score = score.clamp(0.0, 100.0);
        self.updated_at = Utc::now();
    }

    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: serde_json::Value) {
        self.metadata.insert(key, value);
        self.updated_at = Utc::now();
    }

    /// Verify a credential based on the verifier's capabilities
    pub fn verify_credential(
        &self,
        credential: &VerifiableCredential,
        criteria: &VerificationCriteria,
    ) -> Result<VerificationResult, AttestorError> {
        // Check if verifier has the required capability
        let required_capability = self.get_capability_for_credential_type(&criteria.credential_type)?;
        if !self.has_capability(&required_capability) {
            return Err(AttestorError::InvalidSignature(
                format!("Verifier lacks required capability: {:?}", required_capability)
            ));
        }

        // Validate credential structure
        credential.validate()
            .map_err(|e| AttestorError::InvalidSignature(format!("Invalid credential: {}", e)))?;

        // Check required fields
        let mut verified_claims = Vec::new();
        for field in &criteria.required_fields {
            if credential.credential_subject.claims.contains_key(field) {
                verified_claims.push(field.clone());
            }
        }

        // Calculate confidence score based on various factors
        let confidence_score = self.calculate_confidence_score(credential, criteria, &verified_claims);

        Ok(VerificationResult {
            verifier_id: self.id.clone(),
            credential_id: credential.id.clone(),
            verified_claims,
            evidence_level: criteria.minimum_evidence_level.clone(),
            confidence_score,
            verification_method: "manual_review".to_string(), // Could be automated, manual, etc.
            timestamp: Utc::now(),
            notes: None,
            supporting_documents: Vec::new(),
        })
    }

    /// Get the required capability for a credential type
    fn get_capability_for_credential_type(&self, credential_type: &str) -> Result<VerificationCapability, AttestorError> {
        match credential_type {
            "KycCredential" => Ok(VerificationCapability::KycVerification),
            "AgeVerificationCredential" => Ok(VerificationCapability::AgeVerification),
            "UniversityDegreeCredential" => Ok(VerificationCapability::EducationVerification),
            "EmploymentCredential" => Ok(VerificationCapability::EmploymentVerification),
            "IdentityCredential" => Ok(VerificationCapability::IdentityVerification),
            "AddressCredential" => Ok(VerificationCapability::AddressVerification),
            _ => Ok(VerificationCapability::Custom(credential_type.to_string())),
        }
    }

    /// Calculate confidence score for verification
    fn calculate_confidence_score(
        &self,
        credential: &VerifiableCredential,
        criteria: &VerificationCriteria,
        verified_claims: &[String],
    ) -> f64 {
        let mut score = 0.0;

        // Base score from reputation
        score += self.reputation_score * 0.3;

        // Score from verified claims coverage
        let coverage = verified_claims.len() as f64 / criteria.required_fields.len() as f64;
        score += coverage * 40.0;

        // Score from credential freshness
        let age_days = (Utc::now() - credential.issuance_date).num_days();
        let freshness_score = if age_days <= 30 {
            20.0
        } else if age_days <= 90 {
            15.0
        } else if age_days <= 365 {
            10.0
        } else {
            5.0
        };
        score += freshness_score;

        // Score from issuer reputation (simplified)
        score += 10.0; // Would be based on actual issuer reputation

        score.clamp(0.0, 100.0)
    }

    /// Validate verifier's DID document
    pub fn validate_did_document(&self, did_document: &DidDocument) -> Result<(), AttestorError> {
        if did_document.id != self.did {
            return Err(AttestorError::InvalidSignature("DID mismatch".to_string()));
        }

        did_document.validate()
            .map_err(|e| AttestorError::InvalidSignature(format!("Invalid DID document: {}", e)))?;

        Ok(())
    }
}

impl VerificationCapability {
    /// Get human-readable description of the capability
    pub fn description(&self) -> &str {
        match self {
            VerificationCapability::KycVerification => "Know Your Customer verification",
            VerificationCapability::AgeVerification => "Age verification",
            VerificationCapability::EducationVerification => "Education credential verification",
            VerificationCapability::EmploymentVerification => "Employment verification",
            VerificationCapability::IdentityVerification => "Identity document verification",
            VerificationCapability::AddressVerification => "Address verification",
            VerificationCapability::Custom(desc) => desc,
        }
    }
}

impl EvidenceLevel {
    /// Convert to numeric value for comparisons
    pub fn to_numeric(&self) -> u8 {
        match self {
            EvidenceLevel::Low => 1,
            EvidenceLevel::Medium => 2,
            EvidenceLevel::High => 3,
            EvidenceLevel::VeryHigh => 4,
        }
    }
}

impl std::fmt::Display for VerificationCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl std::fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceLevel::Low => write!(f, "Low"),
            EvidenceLevel::Medium => write!(f, "Medium"),
            EvidenceLevel::High => write!(f, "High"),
            EvidenceLevel::VeryHigh => write!(f, "Very High"),
        }
    }
}
