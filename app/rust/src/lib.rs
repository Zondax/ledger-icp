#![no_std]
#![no_builtins]
#![macro_use]

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

#[cfg(test)]
fn debug(_msg: &str) {}

#[cfg(all(
    not(test),
    not(feature = "clippy"),
    not(feature = "fuzzing"),
    target_os = "none"
))]
use core::panic::PanicInfo;

#[cfg(all(
    not(test),
    not(feature = "clippy"),
    not(feature = "fuzzing"),
    target_os = "none"
))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub fn zlog(_msg: &str) {
    cfg_if::cfg_if! {
        if #[cfg(all(not(test), not(feature = "clippy"), not(feature = "fuzzing")))] {
            unsafe {
                zemu_log_stack(_msg.as_bytes().as_ptr());
            }
        } else {
            std::println!("{}", _msg);
        }
    }
}

pub fn check_canary() {
    #[cfg(all(not(test), not(feature = "clippy"), not(feature = "fuzzing")))]
    unsafe {
        _check_canary()
    }
}

extern "C" {
    fn zemu_log_stack(s: *const u8);
    fn _check_canary();
}

#[cfg(all(not(test), not(feature = "clippy"), not(feature = "fuzzing")))]
extern "C" {
    fn pic(link_address: u32) -> u32;
}

// Lets the device breath between computations
#[cfg(test)]
pub(crate) fn log_num(s: &str, number: u32) {
    std::println!("{s}: {number}");
}

pub fn pic_addr(addr: u32) -> u32 {
    cfg_if::cfg_if! {
        if #[cfg(all(not(test), not(feature = "clippy"), not(feature = "fuzzing")))] {
        unsafe {
            pic(addr)
        }
        } else {
            addr
        }
    }
}
