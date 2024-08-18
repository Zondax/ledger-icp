use bolos::{lazy_static, pic::PIC};
#[lazy_static]
pub static mut CONSENT_REQUEST_T: Option<crate::ffi::consent_request::ConsentRequestT> = None;

#[lazy_static]
pub static mut CALL_REQUEST_T: Option<crate::ffi::call_request::CanisterCallT> = None;

#[lazy_static]
pub static mut CERTIFICATE: Option<crate::parser::Certificate<'static>> = None;

#[no_mangle]
pub unsafe extern "C" fn rs_clear_resources() {
    if CONSENT_REQUEST_T.is_some() {
        crate::zlog("clear_resources: consent_request\x00");
        CONSENT_REQUEST_T.take();
    }
    if CALL_REQUEST_T.is_some() {
        crate::zlog("clear_resources: call_request\x00");
        CALL_REQUEST_T.take();
    }
    if CERTIFICATE.is_some() {
        crate::zlog("clear_resources: Certificate\x00");
        CERTIFICATE.take();
    }
}
