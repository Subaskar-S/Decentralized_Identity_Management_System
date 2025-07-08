//! IPFS retrieval operations for identity management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use crate::client::{IpfsClient, ContentType};
use crate::error::IpfsError;
use identity_core::{DidDocument, VerifiableCredential, VerifiablePresentation};

/// Retrieval manager for fetching and caching content
pub struct RetrievalManager {
    client: IpfsClient,
    cache: HashMap<String, CachedContent>,
    cache_ttl: chrono::Duration,
}

/// Cached content with metadata
#[derive(Debug, Clone)]
struct CachedContent {
    data: Vec<u8>,
    content_type: ContentType,
    cached_at: DateTime<Utc>,
    access_count: u64,
}

/// Retrieval options
#[derive(Debug, Clone)]
pub struct RetrievalOptions {
    pub use_cache: bool,
    pub timeout: Option<std::time::Duration>,
    pub verify_integrity: bool,
}

/// Batch retrieval operation
#[derive(Debug, Clone)]
pub struct BatchRetrieval {
    pub hashes: Vec<String>,
    pub options: RetrievalOptions,
}

/// Result of a batch retrieval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRetrievalResult {
    pub successful: HashMap<String, serde_json::Value>,
    pub failed: HashMap<String, String>, // hash -> error message
    pub cache_hits: usize,
    pub cache_misses: usize,
}

/// Content verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub hash: String,
    pub is_valid: bool,
    pub content_type: Option<ContentType>,
    pub size: u64,
    pub errors: Vec<String>,
}

impl RetrievalManager {
    /// Create a new retrieval manager
    pub fn new(client: IpfsClient) -> Self {
        Self {
            client,
            cache: HashMap::new(),
            cache_ttl: chrono::Duration::hours(1), // 1 hour default TTL
        }
    }

    /// Set cache TTL
    pub fn set_cache_ttl(&mut self, ttl: chrono::Duration) {
        self.cache_ttl = ttl;
    }

    /// Retrieve and parse a DID document
    pub async fn get_did_document(&mut self, hash: &str, options: RetrievalOptions) -> Result<DidDocument, IpfsError> {
        let content = self.get_content_with_cache(hash, &options).await?;

        serde_json::from_slice(&content)
            .map_err(|e| IpfsError::StorageError(format!("Failed to parse DID document: {}", e)))
    }

    /// Retrieve and parse a verifiable credential
    pub async fn get_credential(&mut self, hash: &str, options: RetrievalOptions) -> Result<VerifiableCredential, IpfsError> {
        let content = self.get_content_with_cache(hash, &options).await?;

        serde_json::from_slice(&content)
            .map_err(|e| IpfsError::StorageError(format!("Failed to parse credential: {}", e)))
    }

    /// Retrieve and parse a verifiable presentation
    pub async fn get_presentation(&mut self, hash: &str, options: RetrievalOptions) -> Result<VerifiablePresentation, IpfsError> {
        let content = self.get_content_with_cache(hash, &options).await?;

        serde_json::from_slice(&content)
            .map_err(|e| IpfsError::StorageError(format!("Failed to parse presentation: {}", e)))
    }

    /// Retrieve raw content as JSON
    pub async fn get_json(&mut self, hash: &str, options: RetrievalOptions) -> Result<serde_json::Value, IpfsError> {
        let content = self.get_content_with_cache(hash, &options).await?;

        serde_json::from_slice(&content)
            .map_err(|e| IpfsError::StorageError(format!("Failed to parse JSON: {}", e)))
    }

    /// Retrieve raw content
    pub async fn get_raw_content(&mut self, hash: &str, options: RetrievalOptions) -> Result<Vec<u8>, IpfsError> {
        self.get_content_with_cache(hash, &options).await
    }

    /// Execute batch retrieval
    pub async fn execute_batch_retrieval(&mut self, batch: BatchRetrieval) -> BatchRetrievalResult {
        let mut successful = HashMap::new();
        let mut failed = HashMap::new();
        let mut cache_hits = 0;
        let mut cache_misses = 0;

        for hash in batch.hashes {
            // Check cache first if enabled
            if batch.options.use_cache {
                if let Some(cached) = self.get_from_cache(&hash) {
                    cache_hits += 1;
                    match serde_json::from_slice(&cached.data) {
                        Ok(value) => {
                            successful.insert(hash, value);
                            continue;
                        }
                        Err(e) => {
                            failed.insert(hash, format!("Cache deserialization error: {}", e));
                            continue;
                        }
                    }
                }
            }

            cache_misses += 1;

            // Fetch from IPFS
            match self.get_content_with_cache(&hash, &batch.options).await {
                Ok(content) => {
                    match serde_json::from_slice(&content) {
                        Ok(value) => {
                            successful.insert(hash, value);
                        }
                        Err(e) => {
                            failed.insert(hash, format!("Deserialization error: {}", e));
                        }
                    }
                }
                Err(e) => {
                    failed.insert(hash, e.to_string());
                }
            }
        }

        BatchRetrievalResult {
            successful,
            failed,
            cache_hits,
            cache_misses,
        }
    }

    /// Verify content integrity and structure
    pub async fn verify_content(&self, hash: &str, expected_type: Option<ContentType>) -> Result<VerificationResult, IpfsError> {
        let content = self.client.get_content(hash).await?;
        let mut errors = Vec::new();
        let mut is_valid = true;

        // Basic size check
        if content.is_empty() {
            errors.push("Content is empty".to_string());
            is_valid = false;
        }

        // Try to determine content type
        let detected_type = self.detect_content_type(&content);

        // Verify expected type matches detected type
        if let (Some(expected), Some(detected)) = (&expected_type, &detected_type) {
            if expected != detected {
                errors.push(format!("Content type mismatch: expected {:?}, detected {:?}", expected, detected));
                is_valid = false;
            }
        }

        // Try to parse as JSON for structured content
        if let Some(content_type) = &detected_type {
            match content_type {
                ContentType::DidDocument => {
                    if let Err(e) = serde_json::from_slice::<DidDocument>(&content) {
                        errors.push(format!("Invalid DID document structure: {}", e));
                        is_valid = false;
                    }
                }
                ContentType::VerifiableCredential => {
                    if let Err(e) = serde_json::from_slice::<VerifiableCredential>(&content) {
                        errors.push(format!("Invalid credential structure: {}", e));
                        is_valid = false;
                    }
                }
                ContentType::VerifiablePresentation => {
                    if let Err(e) = serde_json::from_slice::<VerifiablePresentation>(&content) {
                        errors.push(format!("Invalid presentation structure: {}", e));
                        is_valid = false;
                    }
                }
                _ => {
                    // For other types, just check if it's valid JSON
                    if let Err(e) = serde_json::from_slice::<serde_json::Value>(&content) {
                        errors.push(format!("Invalid JSON structure: {}", e));
                        is_valid = false;
                    }
                }
            }
        }

        Ok(VerificationResult {
            hash: hash.to_string(),
            is_valid,
            content_type: detected_type,
            size: content.len() as u64,
            errors,
        })
    }

    /// Clear cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> CacheStatistics {
        let total_items = self.cache.len();
        let total_size: usize = self.cache.values().map(|c| c.data.len()).sum();
        let total_access_count: u64 = self.cache.values().map(|c| c.access_count).sum();

        CacheStatistics {
            total_items,
            total_size,
            total_access_count,
            average_access_count: if total_items > 0 { total_access_count / total_items as u64 } else { 0 },
        }
    }

    /// Get content with caching support
    async fn get_content_with_cache(&mut self, hash: &str, options: &RetrievalOptions) -> Result<Vec<u8>, IpfsError> {
        // Check cache first if enabled
        if options.use_cache {
            if let Some(cached) = self.get_from_cache(hash) {
                return Ok(cached.data);
            }
        }

        // Fetch from IPFS
        let content = self.client.get_content(hash).await?;

        // Cache the content if caching is enabled
        if options.use_cache {
            let content_type = self.detect_content_type(&content).unwrap_or(ContentType::Custom("unknown".to_string()));
            self.cache.insert(hash.to_string(), CachedContent {
                data: content.clone(),
                content_type,
                cached_at: Utc::now(),
                access_count: 1,
            });
        }

        Ok(content)
    }

    /// Get content from cache if available and not expired
    fn get_from_cache(&mut self, hash: &str) -> Option<CachedContent> {
        if let Some(cached) = self.cache.get_mut(hash) {
            // Check if cache entry is still valid
            if Utc::now() - cached.cached_at < self.cache_ttl {
                cached.access_count += 1;
                return Some(cached.clone());
            } else {
                // Remove expired entry
                self.cache.remove(hash);
            }
        }
        None
    }

    /// Detect content type from content
    fn detect_content_type(&self, content: &[u8]) -> Option<ContentType> {
        // Try to parse as JSON first
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(content) {
            if let Some(obj) = json.as_object() {
                // Check for DID document
                if obj.contains_key("@context") && obj.contains_key("id") {
                    if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
                        if id.starts_with("did:") {
                            return Some(ContentType::DidDocument);
                        }
                    }
                }

                // Check for verifiable credential
                if obj.contains_key("@context") && obj.contains_key("credentialSubject") {
                    return Some(ContentType::VerifiableCredential);
                }

                // Check for verifiable presentation
                if obj.contains_key("@context") && obj.contains_key("verifiableCredential") {
                    return Some(ContentType::VerifiablePresentation);
                }

                // Default to metadata for other JSON objects
                return Some(ContentType::Metadata);
            }
        }

        None
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatistics {
    pub total_items: usize,
    pub total_size: usize,
    pub total_access_count: u64,
    pub average_access_count: u64,
}

impl Default for RetrievalOptions {
    fn default() -> Self {
        Self {
            use_cache: true,
            timeout: Some(std::time::Duration::from_secs(30)),
            verify_integrity: false,
        }
    }
}

impl BatchRetrieval {
    /// Create a new batch retrieval
    pub fn new(hashes: Vec<String>) -> Self {
        Self {
            hashes,
            options: RetrievalOptions::default(),
        }
    }

    /// Set retrieval options
    pub fn with_options(mut self, options: RetrievalOptions) -> Self {
        self.options = options;
        self
    }

    /// Disable caching for this batch
    pub fn without_cache(mut self) -> Self {
        self.options.use_cache = false;
        self
    }

    /// Enable integrity verification
    pub fn with_verification(mut self) -> Self {
        self.options.verify_integrity = true;
        self
    }
}
