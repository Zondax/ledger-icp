use bolos::{lazy_static, pic::PIC};

use crate::Certificate;

use super::{call_request::CanisterCallT, consent_request::ConsentRequestT};

#[bolos::nvm]
pub static mut MEMORY_CONSENT_REQUEST: [u8; core::mem::size_of::<ConsentRequestT>()];

#[bolos::nvm]
pub static mut MEMORY_CALL_REQUEST: [u8; core::mem::size_of::<CanisterCallT>()];

#[lazy_static]
pub static mut CERTIFICATE: Option<Certificate<'static>> = None;

#[no_mangle]
pub unsafe extern "C" fn rs_clear_resources() {
    // CONSENT_REQUEST_T.take();
    // CALL_REQUEST_T.take();
    CERTIFICATE.take();
}
