//! Fuzz target for strata-codec deserialization.
//!
//! This target fuzzes the core deserialization routines used across the protocol,
//! including deposit transaction auxiliary data parsing. Malformed input should
//! never cause panics or undefined behavior.
//!
//! ## Why This Target is Critical
//!
//! The `strata-codec` is used to decode auxiliary data in SPS-50 tagged transactions.
//! This includes:
//! - Deposit transactions (L1→L2 bridge entry point)
//! - Withdrawal fulfillment transactions (L2→L1 bridge exit)
//!
//! Malformed aux_data from L1 transactions must be handled gracefully.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strata_asm_txs_bridge_v1::deposit::DepositTxHeaderAux;
use strata_asm_txs_bridge_v1::withdrawal_fulfillment::WithdrawalFulfillmentTxHeaderAux;
use strata_codec::decode_buf_exact;

fuzz_target!(|data: &[u8]| {
    // Fuzz DepositTxHeaderAux decoding - critical for L1->L2 deposits
    // This should gracefully handle malformed input without panicking
    let _ = decode_buf_exact::<DepositTxHeaderAux>(data);

    // Fuzz WithdrawalFulfillmentTxHeaderAux decoding - critical for L2->L1 withdrawals
    let _ = decode_buf_exact::<WithdrawalFulfillmentTxHeaderAux>(data);
});
