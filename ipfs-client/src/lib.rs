//! # IPFS Client
//!
//! IPFS integration for decentralized storage of identity metadata,
//! DID documents, and credential proofs.

pub mod client;
pub mod storage;
pub mod retrieval;
pub mod error;

pub use client::*;
pub use storage::*;
pub use retrieval::*;
pub use error::*;
