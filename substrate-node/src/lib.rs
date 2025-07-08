//! # Substrate Node
//!
//! Substrate runtime pallet for decentralized identity management.
//! Handles DID registration, credential hash storage, and on-chain verification.

pub mod did_registry;
pub mod credential_registry;
pub mod verification;

pub use did_registry::*;
pub use credential_registry::*;
pub use verification::*;
