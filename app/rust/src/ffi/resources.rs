use bolos::{lazy_static, pic::PIC};

use crate::{consent_message::msg_info::ConsentInfo, Certificate};

use super::{call_request::CanisterCallT, consent_request::ConsentRequestT};

// NOTE: The call_request anc consent_request were initially defined as Optionals, identical to the
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

#[no_mangle]
pub unsafe extern "C" fn rs_clear_resources() {
    // zeroize data
    _ = MEMORY_CONSENT_REQUEST.write(0, &[0; core::mem::size_of::<ConsentRequestT>()]);
    _ = MEMORY_CALL_REQUEST.write(0, &[0; core::mem::size_of::<CanisterCallT>()]);
    CERTIFICATE.take();
    UI.take();
}
