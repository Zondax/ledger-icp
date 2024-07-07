#![no_std]
#![no_builtins]
#![macro_use]
#![allow(dead_code)]
#![deny(unused_crate_dependencies)]

extern crate no_std_compat as std;

mod ffi;
mod parser;

fn debug(_msg: &str) {}

#[cfg(not(any(test, fuzzing)))]
use core::panic::PanicInfo;

#[cfg(not(any(test, fuzzing)))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
