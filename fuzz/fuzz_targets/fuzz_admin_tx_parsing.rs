//! Fuzz target for admin transaction Borsh deserialization.
//!
//! This target fuzzes the Borsh decoding of administrative transaction payloads.
//! Admin transactions control system upgrades, threshold config changes, and more.
//!
//! ## Why This Target is Critical
//!
//! Admin transactions have elevated privileges. The parser must handle:
//! - Malformed SignedPayload structures
//! - Invalid MultisigAction variants
//! - Corrupted SignatureSet data
//! - Invalid ThresholdConfig updates
//! - Sequence number edge cases
//!
//! Any parsing vulnerability could enable unauthorized admin actions.

#![no_main]

use borsh::BorshDeserialize;
use libfuzzer_sys::fuzz_target;
use strata_asm_txs_admin::parser::SignedPayload;
use strata_crypto::threshold_signature::{IndexedSignature, SignatureSet, ThresholdConfig};

fuzz_target!(|data: &[u8]| {
    // Fuzz complete SignedPayload deserialization (action + signatures)
    let _ = SignedPayload::try_from_slice(data);

    // Fuzz threshold signature types
    let _ = ThresholdConfig::try_from_slice(data);
    let _ = SignatureSet::try_from_slice(data);
    let _ = IndexedSignature::try_from_slice(data);
});
