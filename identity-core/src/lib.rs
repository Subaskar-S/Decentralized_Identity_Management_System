//! # Identity Core
//!
//! Core data structures and functionality for decentralized identity management.
//! This crate implements W3C DID Core and Verifiable Credentials specifications.

pub mod did;
pub mod vc;
pub mod crypto;
pub mod error;
pub mod utils;

pub use did::*;
pub use vc::*;
pub use crypto::*;
pub use error::*;
