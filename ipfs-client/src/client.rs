//! IPFS client implementation for decentralized identity storage

use ipfs_api_backend_hyper::{IpfsApi, IpfsClient as HyperIpfsClient, TryFromUri};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use crate::error::IpfsError;
use identity_core::{DidDocument, VerifiableCredential, VerifiablePresentation};

/// IPFS client for identity management
pub struct IpfsClient {
    client: HyperIpfsClient,
    endpoint: String,
}

/// Metadata for stored content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    pub content_type: ContentType,
    pub hash: String,
    pub size: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub tags: Vec<String>,
    pub encryption: Option<EncryptionInfo>,
}

/// Types of content that can be stored
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ContentType {
    DidDocument,
    VerifiableCredential,
    VerifiablePresentation,
    AttestationProof,
    RevocationList,
    Schema,
    Metadata,
    Custom(String),
}

/// Encryption information for stored content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub algorithm: String,
    pub key_id: String,
    pub nonce: Option<String>,
}

/// Storage result containing hash and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageResult {
    pub hash: String,
    pub metadata: ContentMetadata,
}

impl IpfsClient {
    /// Create a new IPFS client
    pub fn new(endpoint: &str) -> Result<Self, IpfsError> {
        let client = HyperIpfsClient::from_str(endpoint)
            .map_err(|e| IpfsError::ConnectionError(format!("Failed to create IPFS client: {}", e)))?;

        Ok(Self {
            client,
            endpoint: endpoint.to_string(),
        })
    }

    /// Create a client with default local endpoint
    pub fn new_local() -> Result<Self, IpfsError> {
        Self::new("http://127.0.0.1:5001")
    }

    /// Test connection to IPFS node
    pub async fn test_connection(&self) -> Result<bool, IpfsError> {
        match self.client.version().await {
            Ok(_) => Ok(true),
            Err(e) => Err(IpfsError::ConnectionError(format!("Connection test failed: {}", e))),
        }
    }

    /// Store a DID document on IPFS
    pub async fn store_did_document(&self, did_doc: &DidDocument) -> Result<StorageResult, IpfsError> {
        let content = serde_json::to_vec(did_doc)
            .map_err(|e| IpfsError::StorageError(format!("Serialization failed: {}", e)))?;

        let metadata = ContentMetadata {
            content_type: ContentType::DidDocument,
            hash: String::new(), // Will be filled after upload
            size: content.len() as u64,
            created_at: chrono::Utc::now(),
            tags: vec!["did".to_string(), "document".to_string()],
            encryption: None,
        };

        self.store_content(&content, metadata).await
    }

    /// Store a verifiable credential on IPFS
    pub async fn store_credential(&self, credential: &VerifiableCredential) -> Result<StorageResult, IpfsError> {
        let content = serde_json::to_vec(credential)
            .map_err(|e| IpfsError::StorageError(format!("Serialization failed: {}", e)))?;

        let metadata = ContentMetadata {
            content_type: ContentType::VerifiableCredential,
            hash: String::new(),
            size: content.len() as u64,
            created_at: chrono::Utc::now(),
            tags: vec!["credential".to_string(), "verifiable".to_string()],
            encryption: None,
        };

        self.store_content(&content, metadata).await
    }

    /// Store a verifiable presentation on IPFS
    pub async fn store_presentation(&self, presentation: &VerifiablePresentation) -> Result<StorageResult, IpfsError> {
        let content = serde_json::to_vec(presentation)
            .map_err(|e| IpfsError::StorageError(format!("Serialization failed: {}", e)))?;

        let metadata = ContentMetadata {
            content_type: ContentType::VerifiablePresentation,
            hash: String::new(),
            size: content.len() as u64,
            created_at: chrono::Utc::now(),
            tags: vec!["presentation".to_string(), "verifiable".to_string()],
            encryption: None,
        };

        self.store_content(&content, metadata).await
    }

    /// Store attestation proof on IPFS
    pub async fn store_attestation_proof(&self, proof: &serde_json::Value) -> Result<StorageResult, IpfsError> {
        let content = serde_json::to_vec(proof)
            .map_err(|e| IpfsError::StorageError(format!("Serialization failed: {}", e)))?;

        let metadata = ContentMetadata {
            content_type: ContentType::AttestationProof,
            hash: String::new(),
            size: content.len() as u64,
            created_at: chrono::Utc::now(),
            tags: vec!["attestation".to_string(), "proof".to_string()],
            encryption: None,
        };

        self.store_content(&content, metadata).await
    }

    /// Store arbitrary content with metadata
    pub async fn store_content(&self, content: &[u8], mut metadata: ContentMetadata) -> Result<StorageResult, IpfsError> {
        let content_vec = content.to_vec();
        let cursor = Cursor::new(content_vec);

        let response = self.client.add(cursor).await
            .map_err(|e| IpfsError::StorageError(format!("IPFS add failed: {}", e)))?;

        let hash = response.hash.clone();
        metadata.hash = response.hash;

        Ok(StorageResult {
            hash,
            metadata,
        })
    }

    /// Retrieve content by hash
    pub async fn get_content(&self, hash: &str) -> Result<Vec<u8>, IpfsError> {
        use futures::TryStreamExt;

        let response = self.client.cat(hash);

        let chunks: Vec<bytes::Bytes> = response.try_collect().await
            .map_err(|e| IpfsError::StorageError(format!("Failed to read content: {}", e)))?;

        let mut content = Vec::new();
        for chunk in chunks {
            content.extend_from_slice(&chunk);
        }

        Ok(content)
    }

    /// Retrieve and deserialize a DID document
    pub async fn get_did_document(&self, hash: &str) -> Result<DidDocument, IpfsError> {
        let content = self.get_content(hash).await?;

        serde_json::from_slice(&content)
            .map_err(|e| IpfsError::StorageError(format!("Failed to deserialize DID document: {}", e)))
    }

    /// Retrieve and deserialize a verifiable credential
    pub async fn get_credential(&self, hash: &str) -> Result<VerifiableCredential, IpfsError> {
        let content = self.get_content(hash).await?;

        serde_json::from_slice(&content)
            .map_err(|e| IpfsError::StorageError(format!("Failed to deserialize credential: {}", e)))
    }

    /// Retrieve and deserialize a verifiable presentation
    pub async fn get_presentation(&self, hash: &str) -> Result<VerifiablePresentation, IpfsError> {
        let content = self.get_content(hash).await?;

        serde_json::from_slice(&content)
            .map_err(|e| IpfsError::StorageError(format!("Failed to deserialize presentation: {}", e)))
    }

    /// Pin content to ensure it stays available
    pub async fn pin_content(&self, hash: &str) -> Result<(), IpfsError> {
        self.client.pin_add(hash, false).await
            .map_err(|e| IpfsError::StorageError(format!("Pin failed: {}", e)))?;

        Ok(())
    }

    /// Unpin content
    pub async fn unpin_content(&self, hash: &str) -> Result<(), IpfsError> {
        self.client.pin_rm(hash, false).await
            .map_err(|e| IpfsError::StorageError(format!("Unpin failed: {}", e)))?;

        Ok(())
    }

    /// List pinned content
    pub async fn list_pinned(&self) -> Result<Vec<String>, IpfsError> {
        let response = self.client.pin_ls(None, None).await
            .map_err(|e| IpfsError::StorageError(format!("Pin list failed: {}", e)))?;

        Ok(response.keys.into_keys().collect())
    }

    /// Get node information
    pub async fn get_node_info(&self) -> Result<serde_json::Value, IpfsError> {
        let version = self.client.version().await
            .map_err(|e| IpfsError::ConnectionError(format!("Version check failed: {}", e)))?;

        Ok(serde_json::json!({
            "version": version.version,
            "commit": version.commit,
            "repo": version.repo,
            "system": version.system,
            "golang": version.golang
        }))
    }
}

impl ContentType {
    /// Get the MIME type for the content
    pub fn mime_type(&self) -> &str {
        match self {
            ContentType::DidDocument => "application/did+ld+json",
            ContentType::VerifiableCredential => "application/vc+ld+json",
            ContentType::VerifiablePresentation => "application/vp+ld+json",
            ContentType::AttestationProof => "application/json",
            ContentType::RevocationList => "application/json",
            ContentType::Schema => "application/schema+json",
            ContentType::Metadata => "application/json",
            ContentType::Custom(_) => "application/octet-stream",
        }
    }

    /// Get file extension for the content type
    pub fn file_extension(&self) -> &str {
        match self {
            ContentType::DidDocument => ".did.json",
            ContentType::VerifiableCredential => ".vc.json",
            ContentType::VerifiablePresentation => ".vp.json",
            ContentType::AttestationProof => ".proof.json",
            ContentType::RevocationList => ".revocation.json",
            ContentType::Schema => ".schema.json",
            ContentType::Metadata => ".meta.json",
            ContentType::Custom(_) => ".bin",
        }
    }
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::DidDocument => write!(f, "DID Document"),
            ContentType::VerifiableCredential => write!(f, "Verifiable Credential"),
            ContentType::VerifiablePresentation => write!(f, "Verifiable Presentation"),
            ContentType::AttestationProof => write!(f, "Attestation Proof"),
            ContentType::RevocationList => write!(f, "Revocation List"),
            ContentType::Schema => write!(f, "Schema"),
            ContentType::Metadata => write!(f, "Metadata"),
            ContentType::Custom(name) => write!(f, "{}", name),
        }
    }
}
