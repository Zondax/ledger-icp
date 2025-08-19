#![allow(static_mut_refs)]

use bolos::{lazy_static, pic::PIC};
use core::ptr::{addr_of, addr_of_mut};

use crate::{consent_message::msg_info::ConsentInfo, Certificate};

use super::{call_request::CanisterCallT, consent_request::ConsentRequestT};

// NOTE: The call_request and consent_request were initially defined as Optionals, identical to the
// certificate. But this approach consumes stacks, so we move it to flash, saving us 244 bytes of
// stack, unfortunately, this did not help.
// it is better to keep them as optionals, but we can change it back overtime.
#[bolos::nvm]
pub static mut MEMORY_CONSENT_REQUEST: [u8; core::mem::size_of::<ConsentRequestT>()];

#[bolos::nvm]
pub static mut MEMORY_CALL_REQUEST: [u8; core::mem::size_of::<CanisterCallT>()];

#[lazy_static]
pub static mut CERTIFICATE: Option<Certificate<'static>> = None;

#[lazy_static]
pub static mut UI: Option<ConsentInfo<'static>> = None;

// Safe wrapper functions for static access
pub(crate) unsafe fn clear_consent_request() {
    let ptr = addr_of_mut!(MEMORY_CONSENT_REQUEST);
    _ = (*ptr).write(0, &[0; core::mem::size_of::<ConsentRequestT>()]);
}

pub(crate) unsafe fn clear_call_request() {
    let ptr = addr_of_mut!(MEMORY_CALL_REQUEST);
    _ = (*ptr).write(0, &[0; core::mem::size_of::<CanisterCallT>()]);
}

pub(crate) unsafe fn write_call_request(data: &[u8]) -> Result<(), ()> {
    let ptr = addr_of_mut!(MEMORY_CALL_REQUEST);
    (*ptr).write(0, data).map_err(|_| ())
}

pub(crate) unsafe fn get_call_request_memory(
) -> &'static [u8; core::mem::size_of::<CanisterCallT>()] {
    let ptr = addr_of!(MEMORY_CALL_REQUEST);
    &*ptr
}

pub(crate) unsafe fn write_consent_request(data: &[u8]) -> Result<(), ()> {
    let ptr = addr_of_mut!(MEMORY_CONSENT_REQUEST);
    (*ptr).write(0, data).map_err(|_| ())
}

pub(crate) unsafe fn get_consent_request_memory(
) -> &'static [u8; core::mem::size_of::<ConsentRequestT>()] {
    let ptr = addr_of!(MEMORY_CONSENT_REQUEST);
    &*ptr
}

pub(crate) unsafe fn get_ui() -> Option<&'static ConsentInfo<'static>> {
    let ptr = addr_of!(UI);
    (*ptr).as_ref()
}

pub(crate) unsafe fn set_ui(ui: ConsentInfo<'static>) {
    let ptr = addr_of_mut!(UI);
    (*ptr).replace(ui);
}

pub(crate) unsafe fn take_ui() -> Option<ConsentInfo<'static>> {
    let ptr = addr_of_mut!(UI);
    (*ptr).take()
}

pub(crate) unsafe fn set_certificate(cert: Certificate<'static>) {
    let ptr = addr_of_mut!(CERTIFICATE);
    (*ptr).replace(cert);
}

pub(crate) unsafe fn take_certificate() -> Option<Certificate<'static>> {
    let ptr = addr_of_mut!(CERTIFICATE);
    (*ptr).take()
}

pub(crate) unsafe fn certificate_is_some() -> bool {
    let ptr = addr_of!(CERTIFICATE);
    (*ptr).is_some()
}

pub(crate) unsafe fn ui_is_some() -> bool {
    let ptr = addr_of!(UI);
    (*ptr).is_some()
}

#[no_mangle]
pub unsafe extern "C" fn rs_clear_resources() {
    // zeroize data
    clear_consent_request();
    clear_call_request();
    take_certificate();
    take_ui();
}
