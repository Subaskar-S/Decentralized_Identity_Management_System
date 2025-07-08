//! Verifiable Credentials implementation following W3C VC Data Model

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use crate::error::IdentityError;
use crate::utils::generate_id;

/// Verifiable Credential as per W3C VC Data Model
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: Issuer,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: DateTime<Utc>,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<Vec<CredentialSchema>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<Proof>>,
}

/// Issuer can be a string (DID) or an object with additional properties
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Issuer {
    Did(String),
    Object {
        id: String,
        #[serde(flatten)]
        properties: HashMap<String, serde_json::Value>,
    },
}

/// Credential Subject containing the claims
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(flatten)]
    pub claims: HashMap<String, serde_json::Value>,
}

/// Credential Status for revocation checking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
    #[serde(flatten)]
    pub properties: HashMap<String, serde_json::Value>,
}

/// Credential Schema for validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialSchema {
    pub id: String,
    #[serde(rename = "type")]
    pub schema_type: String,
}

/// Cryptographic proof for the credential
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    #[serde(flatten)]
    pub additional_properties: HashMap<String, serde_json::Value>,
}

/// Verifiable Presentation containing one or more credentials
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub presentation_type: Vec<String>,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<Proof>>,
}

/// Credential types commonly used
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialType {
    VerifiableCredential,
    UniversityDegreeCredential,
    DriverLicenseCredential,
    KycCredential,
    AgeVerificationCredential,
    Custom(String),
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::VerifiableCredential => write!(f, "VerifiableCredential"),
            CredentialType::UniversityDegreeCredential => write!(f, "UniversityDegreeCredential"),
            CredentialType::DriverLicenseCredential => write!(f, "DriverLicenseCredential"),
            CredentialType::KycCredential => write!(f, "KycCredential"),
            CredentialType::AgeVerificationCredential => write!(f, "AgeVerificationCredential"),
            CredentialType::Custom(t) => write!(f, "{}", t),
        }
    }
}

impl VerifiableCredential {
    /// Create a new Verifiable Credential
    pub fn new(
        issuer_did: String,
        subject_id: Option<String>,
        claims: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
            ],
            id: format!("urn:uuid:{}", generate_id()),
            credential_type: vec!["VerifiableCredential".to_string()],
            issuer: Issuer::Did(issuer_did),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: subject_id,
                claims,
            },
            credential_status: None,
            credential_schema: None,
            proof: None,
        }
    }

    /// Add a credential type
    pub fn add_type(&mut self, credential_type: CredentialType) {
        let type_str = credential_type.to_string();
        if !self.credential_type.contains(&type_str) {
            self.credential_type.push(type_str);
        }
    }

    /// Set expiration date
    pub fn set_expiration(&mut self, expiration: DateTime<Utc>) {
        self.expiration_date = Some(expiration);
    }

    /// Add credential status for revocation
    pub fn set_status(&mut self, status: CredentialStatus) {
        self.credential_status = Some(status);
    }

    /// Add a proof to the credential
    pub fn add_proof(&mut self, proof: Proof) {
        if self.proof.is_none() {
            self.proof = Some(Vec::new());
        }
        self.proof.as_mut().unwrap().push(proof);
    }

    /// Validate the credential structure
    pub fn validate(&self) -> Result<(), IdentityError> {
        // Check required fields
        if self.credential_type.is_empty() {
            return Err(IdentityError::InvalidCredential("Credential must have at least one type".to_string()));
        }

        if !self.credential_type.contains(&"VerifiableCredential".to_string()) {
            return Err(IdentityError::InvalidCredential("Credential must include 'VerifiableCredential' type".to_string()));
        }

        // Validate issuer
        match &self.issuer {
            Issuer::Did(did) => {
                if !did.starts_with("did:") {
                    return Err(IdentityError::InvalidCredential("Issuer must be a valid DID".to_string()));
                }
            }
            Issuer::Object { id, .. } => {
                if !id.starts_with("did:") {
                    return Err(IdentityError::InvalidCredential("Issuer ID must be a valid DID".to_string()));
                }
            }
        }

        // Check expiration
        if let Some(exp) = self.expiration_date {
            if exp <= Utc::now() {
                return Err(IdentityError::InvalidCredential("Credential has expired".to_string()));
            }
        }

        Ok(())
    }

    /// Check if the credential is expired
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expiration_date {
            exp <= Utc::now()
        } else {
            false
        }
    }

    /// Get the issuer DID
    pub fn get_issuer_did(&self) -> &str {
        match &self.issuer {
            Issuer::Did(did) => did,
            Issuer::Object { id, .. } => id,
        }
    }
}

impl VerifiablePresentation {
    /// Create a new Verifiable Presentation
    pub fn new(credentials: Vec<VerifiableCredential>, holder: Option<String>) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
            ],
            id: Some(format!("urn:uuid:{}", generate_id())),
            presentation_type: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: credentials,
            holder,
            proof: None,
        }
    }

    /// Add a proof to the presentation
    pub fn add_proof(&mut self, proof: Proof) {
        if self.proof.is_none() {
            self.proof = Some(Vec::new());
        }
        self.proof.as_mut().unwrap().push(proof);
    }

    /// Validate the presentation
    pub fn validate(&self) -> Result<(), IdentityError> {
        // Validate all contained credentials
        for credential in &self.verifiable_credential {
            credential.validate()?;
        }

        Ok(())
    }
}
