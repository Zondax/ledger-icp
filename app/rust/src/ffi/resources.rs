use bolos::{lazy_static, pic::PIC};

use crate::Certificate;

use super::{call_request::CanisterCallT, consent_request::ConsentRequestT};
#[lazy_static]
pub static mut CONSENT_REQUEST_T: Option<ConsentRequestT> = None;

#[lazy_static]
pub static mut CALL_REQUEST_T: Option<CanisterCallT> = None;

#[lazy_static]
pub static mut CERTIFICATE: Option<Certificate<'static>> = None;

#[no_mangle]
pub unsafe extern "C" fn rs_clear_resources() {
    CONSENT_REQUEST_T.take();
    CALL_REQUEST_T.take();
    CERTIFICATE.take();
}
