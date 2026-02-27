#![no_main]

use libfuzzer_sys::fuzz_target;
use ssz::Decode;
use strata_ol_chain_types_new::{
    OLBlock, OLBlockBody, OLBlockHeader, OLL1Update, OLTransaction, OLTxSegment,
    SignedOLBlockHeader,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Byte executor: first byte selects the decoding target
    let (selector, payload) = data.split_first().unwrap();

    match selector % 7 {
        // 0 → Full OL block
        0 => {
            let _ = OLBlock::from_ssz_bytes(payload);
        }

        // 1 → Block header
        1 => {
            let _ = OLBlockHeader::from_ssz_bytes(payload);
        }

        // 2 → Signed block header
        2 => {
            let _ = SignedOLBlockHeader::from_ssz_bytes(payload);
        }

        // 3 → Block body
        3 => {
            let _ = OLBlockBody::from_ssz_bytes(payload);
        }

        // 4 → Transaction segment
        4 => {
            let _ = OLTxSegment::from_ssz_bytes(payload);
        }

        // 5 → L1 update
        5 => {
            let _ = OLL1Update::from_ssz_bytes(payload);
        }

        // 6 → Individual transaction (nested inside blocks)
        _ => {
            let _ = OLTransaction::from_ssz_bytes(payload);
        }
    }
});
