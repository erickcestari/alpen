//! Fuzz target for threshold signature verification.
//!
//! This target fuzzes the ECDSA threshold signature verification logic.
//! This is used by the admin subprotocol for multisig operations.
//!
//! ## Why This Target is Critical
//!
//! Threshold signatures protect admin operations. The verifier must handle:
//! - Invalid signature formats (wrong length, invalid recovery IDs)
//! - Out-of-bounds signer indices
//! - Duplicate signer indices
//! - Invalid public keys in ThresholdConfig
//! - Edge cases in BIP-137 signature format normalization
//! - Threshold boundary conditions
//!
//! Any bypass here could allow unauthorized admin actions.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::num::NonZero;
use strata_crypto::{
    keys::compressed::CompressedPublicKey,
    threshold_signature::{verify_threshold_signatures, IndexedSignature, ThresholdConfig},
};

/// Fuzzed input for threshold signature verification.
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Raw public key bytes (33 bytes each for compressed keys)
    key_bytes: Vec<[u8; 33]>,
    /// Threshold value
    threshold: u8,
    /// Signatures with indices
    signatures: Vec<FuzzedSignature>,
    /// Message hash
    message_hash: [u8; 32],
}

/// A fuzzed signature with arbitrary bytes.
#[derive(Debug, Arbitrary)]
struct FuzzedSignature {
    /// Signer index
    index: u8,
    /// 65-byte signature (header + r + s)
    signature: [u8; 65],
}

fuzz_target!(|input: FuzzInput| {
    // Skip if no keys
    if input.key_bytes.is_empty() {
        return;
    }

    // Try to parse public keys (many will be invalid, which is fine)
    let keys: Vec<CompressedPublicKey> = input
        .key_bytes
        .iter()
        .filter_map(|bytes| {
            // Try to create a valid secp256k1 public key
            secp256k1::PublicKey::from_slice(bytes)
                .ok()
                .map(CompressedPublicKey::from)
        })
        .collect();

    // Need at least one valid key
    if keys.is_empty() {
        return;
    }

    // Create threshold (must be non-zero and <= keys.len())
    let threshold = match NonZero::new(input.threshold.max(1).min(keys.len() as u8)) {
        Some(t) => t,
        None => return,
    };

    // Try to create config (may fail due to duplicate keys, etc.)
    let config = match ThresholdConfig::try_new(keys, threshold) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Convert fuzzed signatures to IndexedSignature
    let signatures: Vec<IndexedSignature> = input
        .signatures
        .iter()
        .map(|s| IndexedSignature::new(s.index, s.signature))
        .collect();

    // Verify signatures - this should never panic regardless of input
    let _ = verify_threshold_signatures(&config, &signatures, &input.message_hash);
});
