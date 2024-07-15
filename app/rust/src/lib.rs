#![no_std]
#![no_builtins]
#![macro_use]
#![allow(dead_code)]
#![deny(unused_crate_dependencies)]

extern crate no_std_compat as std;

mod constants;
mod error;
mod ffi;
mod parser;
mod utils;

pub use parser::*;

fn debug(_msg: &str) {}

#[cfg(not(any(test, fuzzing)))]
use core::panic::PanicInfo;

#[cfg(not(any(test, fuzzing)))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub fn zlog(_msg: &str) {
    #[cfg(not(test))]
    unsafe {
        zemu_log_stack(_msg.as_bytes().as_ptr());
    }
}

extern "C" {
    fn zemu_log_stack(s: *const u8);
}
