#![no_main]

use libfuzzer_sys::fuzz_target;
use ssz::Decode;
use strata_ol_chain_types_new::{
    GamTxPayload, OLLog, OLTransaction, SnarkAccountUpdateTxPayload, TransactionAttachment,
    TransactionPayload,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Byte executor: first byte selects execution path
    let (selector, payload) = data.split_first().unwrap();

    match selector % 6 {
        // 0 → Full OL transaction
        0 => {
            let _ = OLTransaction::from_ssz_bytes(payload);
        }

        // 1 → TransactionPayload union
        1 => {
            let _ = TransactionPayload::from_ssz_bytes(payload);
        }

        // 2 → GAM payload
        2 => {
            let _ = GamTxPayload::from_ssz_bytes(payload);
        }

        // 3 → Snark account update payload
        3 => {
            let _ = SnarkAccountUpdateTxPayload::from_ssz_bytes(payload);
        }

        // 4 → Transaction attachment metadata
        4 => {
            let _ = TransactionAttachment::from_ssz_bytes(payload);
        }

        // 5 → OL log
        _ => {
            let _ = OLLog::from_ssz_bytes(payload);
        }
    }
});
