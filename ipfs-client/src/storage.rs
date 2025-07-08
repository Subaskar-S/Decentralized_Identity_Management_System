//! IPFS storage operations for identity management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use crate::client::{IpfsClient, ContentType, StorageResult, ContentMetadata};
use crate::error::IpfsError;
use identity_core::{DidDocument, VerifiableCredential, VerifiablePresentation};

/// Storage manager for organizing and tracking stored content
pub struct StorageManager {
    client: IpfsClient,
    content_index: HashMap<String, ContentMetadata>,
    tags_index: HashMap<String, Vec<String>>, // tag -> list of hashes
}

/// Batch storage operation
#[derive(Debug, Clone)]
pub struct BatchOperation {
    pub operations: Vec<StorageOperation>,
}

/// Individual storage operation
#[derive(Debug, Clone)]
pub enum StorageOperation {
    StoreDid {
        did_doc: DidDocument,
        tags: Vec<String>,
    },
    StoreCredential {
        credential: VerifiableCredential,
        tags: Vec<String>,
    },
    StorePresentation {
        presentation: VerifiablePresentation,
        tags: Vec<String>,
    },
    StoreJson {
        data: serde_json::Value,
        content_type: ContentType,
        tags: Vec<String>,
    },
}

/// Result of a batch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub successful: Vec<StorageResult>,
    pub failed: Vec<(usize, String)>, // operation index and error message
    pub total_size: u64,
    pub total_operations: usize,
}

/// Search criteria for finding stored content
#[derive(Debug, Clone)]
pub struct SearchCriteria {
    pub content_type: Option<ContentType>,
    pub tags: Vec<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
}

impl StorageManager {
    /// Create a new storage manager
    pub fn new(client: IpfsClient) -> Self {
        Self {
            client,
            content_index: HashMap::new(),
            tags_index: HashMap::new(),
        }
    }

    /// Store content with automatic indexing
    pub async fn store_with_index(
        &mut self,
        operation: StorageOperation,
    ) -> Result<StorageResult, IpfsError> {
        let result = match operation {
            StorageOperation::StoreDid { did_doc, tags } => {
                let mut result = self.client.store_did_document(&did_doc).await?;
                result.metadata.tags.extend(tags);
                result
            }
            StorageOperation::StoreCredential { credential, tags } => {
                let mut result = self.client.store_credential(&credential).await?;
                result.metadata.tags.extend(tags);
                result
            }
            StorageOperation::StorePresentation { presentation, tags } => {
                let mut result = self.client.store_presentation(&presentation).await?;
                result.metadata.tags.extend(tags);
                result
            }
            StorageOperation::StoreJson { data, content_type, tags } => {
                let content = serde_json::to_vec(&data)
                    .map_err(|e| IpfsError::StorageError(format!("Serialization failed: {}", e)))?;

                let metadata = ContentMetadata {
                    content_type,
                    hash: String::new(),
                    size: content.len() as u64,
                    created_at: Utc::now(),
                    tags,
                    encryption: None,
                };

                self.client.store_content(&content, metadata).await?
            }
        };

        // Update indexes
        self.update_indexes(&result);

        Ok(result)
    }

    /// Execute a batch of storage operations
    pub async fn execute_batch(&mut self, batch: BatchOperation) -> BatchResult {
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        let mut total_size = 0u64;

        for (index, operation) in batch.operations.into_iter().enumerate() {
            match self.store_with_index(operation).await {
                Ok(result) => {
                    total_size += result.metadata.size;
                    successful.push(result);
                }
                Err(e) => {
                    failed.push((index, e.to_string()));
                }
            }
        }

        BatchResult {
            total_operations: successful.len() + failed.len(),
            successful,
            failed,
            total_size,
        }
    }

    /// Search for content based on criteria
    pub fn search(&self, criteria: SearchCriteria) -> Vec<&ContentMetadata> {
        self.content_index
            .values()
            .filter(|&metadata| self.matches_criteria(metadata, &criteria))
            .collect()
    }

    /// Find content by tags
    pub fn find_by_tags(&self, tags: &[String]) -> Vec<&ContentMetadata> {
        let mut results = Vec::new();

        for tag in tags {
            if let Some(hashes) = self.tags_index.get(tag) {
                for hash in hashes {
                    if let Some(metadata) = self.content_index.get(hash) {
                        if !results.iter().any(|m: &&ContentMetadata| m.hash == metadata.hash) {
                            results.push(metadata);
                        }
                    }
                }
            }
        }

        results
    }

    /// Get content metadata by hash
    pub fn get_metadata(&self, hash: &str) -> Option<&ContentMetadata> {
        self.content_index.get(hash)
    }

    /// List all stored content
    pub fn list_all(&self) -> Vec<&ContentMetadata> {
        self.content_index.values().collect()
    }

    /// Get storage statistics
    pub fn get_statistics(&self) -> StorageStatistics {
        let total_items = self.content_index.len();
        let total_size: u64 = self.content_index.values().map(|m| m.size).sum();

        let mut type_counts = HashMap::new();
        for metadata in self.content_index.values() {
            *type_counts.entry(metadata.content_type.clone()).or_insert(0) += 1;
        }

        StorageStatistics {
            total_items,
            total_size,
            type_counts,
            total_tags: self.tags_index.len(),
        }
    }

    /// Update internal indexes
    fn update_indexes(&mut self, result: &StorageResult) {
        let hash = result.hash.clone();

        // Update content index
        self.content_index.insert(hash.clone(), result.metadata.clone());

        // Update tags index
        for tag in &result.metadata.tags {
            self.tags_index
                .entry(tag.clone())
                .or_insert_with(Vec::new)
                .push(hash.clone());
        }
    }

    /// Check if metadata matches search criteria
    fn matches_criteria(&self, metadata: &ContentMetadata, criteria: &SearchCriteria) -> bool {
        // Check content type
        if let Some(ref content_type) = criteria.content_type {
            if metadata.content_type != *content_type {
                return false;
            }
        }

        // Check tags (all must be present)
        if !criteria.tags.is_empty() {
            for tag in &criteria.tags {
                if !metadata.tags.contains(tag) {
                    return false;
                }
            }
        }

        // Check date range
        if let Some(after) = criteria.created_after {
            if metadata.created_at <= after {
                return false;
            }
        }

        if let Some(before) = criteria.created_before {
            if metadata.created_at >= before {
                return false;
            }
        }

        // Check size range
        if let Some(min_size) = criteria.min_size {
            if metadata.size < min_size {
                return false;
            }
        }

        if let Some(max_size) = criteria.max_size {
            if metadata.size > max_size {
                return false;
            }
        }

        true
    }
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatistics {
    pub total_items: usize,
    pub total_size: u64,
    pub type_counts: HashMap<ContentType, usize>,
    pub total_tags: usize,
}

impl BatchOperation {
    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Add a DID document to the batch
    pub fn add_did_document(mut self, did_doc: DidDocument, tags: Vec<String>) -> Self {
        self.operations.push(StorageOperation::StoreDid { did_doc, tags });
        self
    }

    /// Add a credential to the batch
    pub fn add_credential(mut self, credential: VerifiableCredential, tags: Vec<String>) -> Self {
        self.operations.push(StorageOperation::StoreCredential { credential, tags });
        self
    }

    /// Add a presentation to the batch
    pub fn add_presentation(mut self, presentation: VerifiablePresentation, tags: Vec<String>) -> Self {
        self.operations.push(StorageOperation::StorePresentation { presentation, tags });
        self
    }

    /// Add JSON data to the batch
    pub fn add_json(mut self, data: serde_json::Value, content_type: ContentType, tags: Vec<String>) -> Self {
        self.operations.push(StorageOperation::StoreJson { data, content_type, tags });
        self
    }

    /// Get the number of operations in the batch
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

impl Default for BatchOperation {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchCriteria {
    /// Create new search criteria
    pub fn new() -> Self {
        Self {
            content_type: None,
            tags: Vec::new(),
            created_after: None,
            created_before: None,
            min_size: None,
            max_size: None,
        }
    }

    /// Filter by content type
    pub fn with_content_type(mut self, content_type: ContentType) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Filter by tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Filter by creation date range
    pub fn with_date_range(mut self, after: Option<DateTime<Utc>>, before: Option<DateTime<Utc>>) -> Self {
        self.created_after = after;
        self.created_before = before;
        self
    }

    /// Filter by size range
    pub fn with_size_range(mut self, min: Option<u64>, max: Option<u64>) -> Self {
        self.min_size = min;
        self.max_size = max;
        self
    }
}

impl Default for SearchCriteria {
    fn default() -> Self {
        Self::new()
    }
}
