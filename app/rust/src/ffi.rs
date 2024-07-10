use crate::constants::{BLS_PUBLIC_KEY_SIZE, BLS_SIGNATURE_SIZE};
use bls_signature::verify_bls_signature;

/// The signature must be exactly 48 bytes (compressed G1 element)
/// The key must be exactly 96 bytes (compressed G2 element)
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// but should be safe as long as input data meets the size requirements.
#[no_mangle]
pub unsafe extern "C" fn verify_bls_sign(
    msg: *const u8,
    msg_len: u16,
    key: *const u8,
    sig: *const u8,
) -> u8 {
    // Check for null pointers before converting to slices
    if msg.is_null() || key.is_null() || sig.is_null() {
        return false as u8;
    }

    let msg = std::slice::from_raw_parts(msg, msg_len as usize);
    let key = std::slice::from_raw_parts(key, BLS_PUBLIC_KEY_SIZE);
    let sig = std::slice::from_raw_parts(sig, BLS_SIGNATURE_SIZE);

    verify_bls_signature(sig, msg, key).is_ok() as u8
}
