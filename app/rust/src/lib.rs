#![no_std]
#![no_builtins]
#![macro_use]
#![allow(dead_code)]
#![deny(unused_crate_dependencies)]

extern crate no_std_compat as std;

use bls_signature::PublicKey;

fn debug(_msg: &str) {}

#[cfg(not(any(test, fuzzing)))]
use core::panic::PanicInfo;

#[cfg(not(any(test, fuzzing)))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// uint16_t bls_sign(const uint8_t *msg, uint16_t msg_len, const uint8_t *sk, uint8_t *sig);
#[no_mangle]
pub unsafe extern "C" fn bls_sign(
    msg: *const u8,
    msg_len: u16,
    sk: *const u8,
    sig: *const u8,
) -> u16 {
    PublicKey::BYTES as u16
}
