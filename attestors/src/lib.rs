//! # Attestors
//!
//! Threshold cryptography and multiparty attestation system for decentralized identity.
//! Implements BLS12-381 threshold signatures for k-of-n credential attestation.

pub mod threshold;
pub mod attestation;
pub mod verifier;
pub mod error;

pub use threshold::*;
pub use attestation::*;
pub use verifier::*;
pub use error::*;
