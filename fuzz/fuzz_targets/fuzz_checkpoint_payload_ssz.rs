//! Fuzz target for checkpoint payload SSZ deserialization.
//!
//! This target fuzzes the SSZ decoding of checkpoint-related structures.
//! Checkpoints are critical for L2 finality and bridge security.
//!
//! ## Why This Target is Critical
//!
//! Checkpoints are posted to L1 and validated by the ASM. The parser must handle:
//! - Invalid SignedCheckpointPayload structures
//! - Malformed CheckpointTip, CheckpointClaim, CheckpointSidecar
//! - Invalid TerminalHeaderComplement data
//! - Corrupted OL log arrays within sidecars
//!
//! Any vulnerability here could allow invalid checkpoints to be accepted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ssz::Decode;
use strata_checkpoint_types_ssz::{
    CheckpointClaim, CheckpointSidecar, CheckpointTip, L2BlockRange, SignedCheckpointPayload,
    TerminalHeaderComplement,
};

fuzz_target!(|data: &[u8]| {
    // Fuzz the signed checkpoint payload (the complete structure posted to L1)
    let _ = SignedCheckpointPayload::from_ssz_bytes(data);

    // Fuzz individual checkpoint components
    let _ = CheckpointTip::from_ssz_bytes(data);
    let _ = CheckpointClaim::from_ssz_bytes(data);
    let _ = CheckpointSidecar::from_ssz_bytes(data);
    let _ = L2BlockRange::from_ssz_bytes(data);
    let _ = TerminalHeaderComplement::from_ssz_bytes(data);
});
