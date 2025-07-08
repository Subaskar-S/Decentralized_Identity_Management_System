//! Verification logic for Substrate

pub fn verify_credential_hash(stored_hash: &[u8], provided_hash: &[u8]) -> bool {
    stored_hash == provided_hash
}
