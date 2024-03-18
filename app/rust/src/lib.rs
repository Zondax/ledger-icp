#![no_std]
#![no_builtins]
#![macro_use]
#![allow(dead_code)]
// #![deny(unused_crate_dependencies)]

extern crate no_std_compat as std;

use bls_signature::verify_bls_signature;

// The signature must be exactly 48 bytes (compressed G1 element)
// The key must be exactly 96 bytes (compressed G2 element)
const BLS_SIGNATURE_SIZE: usize = 48;
const BLS_PUBLIC_KEY_SIZE: usize = 96;

fn debug(_msg: &str) {}

#[cfg(not(any(test, fuzzing)))]
use core::panic::PanicInfo;

#[cfg(not(any(test, fuzzing)))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

extern "C" {
    fn zemu_log_stack(s: *const u8);
    fn check_canary();
}

/// The signature must be exactly 48 bytes (compressed G1 element)
/// The key must be exactly 96 bytes (compressed G2 element)
#[no_mangle]
pub unsafe extern "C" fn verify_bls_sign(
    sig: *const u8,
    msg: *const u8,
    msg_len: u16,
    key: *const u8,
) -> u8 {
    let msg = std::slice::from_raw_parts(msg, msg_len as usize);
    let key = std::slice::from_raw_parts(key, BLS_PUBLIC_KEY_SIZE);
    let sig = std::slice::from_raw_parts(sig, BLS_SIGNATURE_SIZE);

    // let res = verify_bls_signature(sig, msg, key);
    // res.is_ok() as u8
    unsafe {
        check_canary();
    }
    verify_bls(sig, msg, key).is_ok() as u8
}

#[inline(never)]
fn verify_bls(sig: &[u8], msg: &[u8], key: &[u8]) -> Result<(), ()> {
    if verify_bls_signature(sig, msg, key).is_ok() {
        return Ok(());
    }
    Err(())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn check_signature() {
        let s = [
            139, 118, 54, 85, 203, 37, 178, 69, 140, 15, 123, 156, 250, 54, 205, 107, 22, 254, 170,
            98, 234, 151, 252, 248, 245, 75, 211, 209, 237, 75, 135, 119, 53, 244, 174, 38, 241,
            127, 34, 154, 2, 92, 174, 10, 73, 110, 128, 24,
        ];
        let key = [
            136, 241, 121, 119, 242, 65, 192, 110, 129, 119, 65, 77, 158, 13, 150, 144, 28, 235,
            33, 208, 173, 221, 78, 19, 60, 123, 224, 65, 6, 100, 121, 203, 211, 101, 20, 169, 44,
            125, 233, 145, 41, 91, 200, 233, 176, 158, 87, 101, 14, 124, 251, 239, 197, 63, 193,
            29, 63, 169, 173, 27, 106, 244, 66, 35, 18, 131, 154, 12, 85, 56, 162, 240, 100, 125,
            155, 115, 241, 135, 95, 223, 191, 44, 141, 140, 9, 202, 43, 152, 228, 117, 44, 46, 126,
            194, 128, 157,
        ];
        let m = [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
        verify_bls_signature(&s, &m, &key).unwrap();
    }
}
