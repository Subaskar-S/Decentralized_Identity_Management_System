//! DID (Decentralized Identifier) implementation following W3C DID Core specification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use crate::error::IdentityError;

/// DID Document as per W3C DID Core specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod", skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,
    #[serde(rename = "authentication", skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<VerificationRelationship>>,
    #[serde(rename = "assertionMethod", skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<VerificationRelationship>>,
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<VerificationRelationship>>,
    #[serde(rename = "capabilityInvocation", skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<VerificationRelationship>>,
    #[serde(rename = "capabilityDelegation", skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<VerificationRelationship>>,
    #[serde(rename = "service", skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
    #[serde(rename = "created", skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    #[serde(rename = "updated", skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
}

/// Verification Method for DID Document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(flatten)]
    pub public_key: PublicKeyFormat,
}

/// Verification Relationship - can be a string reference or embedded verification method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum VerificationRelationship {
    Reference(String),
    Embedded(VerificationMethod),
}

/// Public Key formats supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum PublicKeyFormat {
    Jwk {
        #[serde(rename = "publicKeyJwk")]
        public_key_jwk: HashMap<String, serde_json::Value>
    },
    Multibase {
        #[serde(rename = "publicKeyMultibase")]
        public_key_multibase: String
    },
    Base58 {
        #[serde(rename = "publicKeyBase58")]
        public_key_base58: String
    },
}

/// Service endpoint for DID Document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: ServiceType,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: ServiceEndpoint,
}

/// Service types as defined in DID spec registries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ServiceType {
    Single(String),
    Multiple(Vec<String>),
}

/// Service endpoint can be a string or object
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ServiceEndpoint {
    Uri(String),
    Map(HashMap<String, serde_json::Value>),
}

/// DID Method types
#[derive(Debug, Clone, PartialEq)]
pub enum DidMethod {
    Web,
    Key,
    Ethr,
    Ion,
    Custom(String),
}

impl std::fmt::Display for DidMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DidMethod::Web => write!(f, "web"),
            DidMethod::Key => write!(f, "key"),
            DidMethod::Ethr => write!(f, "ethr"),
            DidMethod::Ion => write!(f, "ion"),
            DidMethod::Custom(method) => write!(f, "{}", method),
        }
    }
}

impl DidDocument {
    /// Create a new DID Document
    pub fn new(id: String) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id,
            verification_method: None,
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            service: None,
            created: Some(Utc::now()),
            updated: None,
        }
    }

    /// Add a verification method to the DID document
    pub fn add_verification_method(&mut self, method: VerificationMethod) {
        if self.verification_method.is_none() {
            self.verification_method = Some(Vec::new());
        }
        self.verification_method.as_mut().unwrap().push(method);
        self.updated = Some(Utc::now());
    }

    /// Add an authentication method
    pub fn add_authentication(&mut self, auth: VerificationRelationship) {
        if self.authentication.is_none() {
            self.authentication = Some(Vec::new());
        }
        self.authentication.as_mut().unwrap().push(auth);
        self.updated = Some(Utc::now());
    }

    /// Add a service endpoint
    pub fn add_service(&mut self, service: Service) {
        if self.service.is_none() {
            self.service = Some(Vec::new());
        }
        self.service.as_mut().unwrap().push(service);
        self.updated = Some(Utc::now());
    }

    /// Validate the DID document structure
    pub fn validate(&self) -> Result<(), IdentityError> {
        // Check if ID is a valid DID
        if !self.id.starts_with("did:") {
            return Err(IdentityError::InvalidDid("DID must start with 'did:'".to_string()));
        }

        // Validate DID format: did:method:method-specific-id
        let parts: Vec<&str> = self.id.split(':').collect();
        if parts.len() < 3 {
            return Err(IdentityError::InvalidDid("DID must have at least 3 parts separated by ':'".to_string()));
        }

        // Validate verification methods if present
        if let Some(methods) = &self.verification_method {
            for method in methods {
                if !method.id.starts_with(&self.id) && !method.id.starts_with("did:") {
                    return Err(IdentityError::InvalidDid("Verification method ID must be a DID or relative to document DID".to_string()));
                }
            }
        }

        Ok(())
    }

    /// Parse DID method from the DID string
    pub fn get_method(&self) -> Result<DidMethod, IdentityError> {
        let parts: Vec<&str> = self.id.split(':').collect();
        if parts.len() < 2 {
            return Err(IdentityError::InvalidDid("Invalid DID format".to_string()));
        }

        match parts[1] {
            "web" => Ok(DidMethod::Web),
            "key" => Ok(DidMethod::Key),
            "ethr" => Ok(DidMethod::Ethr),
            "ion" => Ok(DidMethod::Ion),
            method => Ok(DidMethod::Custom(method.to_string())),
        }
    }
}
