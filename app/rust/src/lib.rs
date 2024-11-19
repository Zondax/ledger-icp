#![no_std]
#![no_builtins]
#![macro_use]
#![allow(dead_code)]
#![deny(unused_crate_dependencies)]

extern crate no_std_compat as std;

pub mod candid_types;
mod constants;
pub mod error;
mod ffi;
mod parser;
mod principal;
pub mod type_table;
pub mod utils;
pub use principal::Principal;
use zemu_sys as _;
pub mod argument_list;
pub mod candid_header;
#[cfg(test)]
pub mod test_ui;

pub use parser::*;

fn debug(_msg: &str) {}

#[cfg(all(not(test), not(feature = "clippy"), not(feature = "fuzzing")))]
use core::panic::PanicInfo;

#[cfg(all(not(test), not(feature = "clippy"), not(feature = "fuzzing")))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub fn zlog(_msg: &str) {
    #[cfg(not(test))]
    unsafe {
        zemu_log_stack(_msg.as_bytes().as_ptr());
    }
    #[cfg(test)]
    std::println!("{}", _msg);
}

#[cfg(not(test))]
pub fn check_canary() {
    unsafe { check_app_canary() }
}

#[cfg(test)]
pub fn check_canary() {}

extern "C" {
    fn zemu_log_stack(s: *const u8);
    fn check_app_canary();
}
