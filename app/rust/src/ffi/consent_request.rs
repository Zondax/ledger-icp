/*******************************************************************************
*   (c) 2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

use crate::{
    call_request::ConsentMsgRequest, check_canary, constants::*, error::ParserError,
    utils::hash_blob, FromBytes,
};

use core::mem::MaybeUninit;

use super::resources::CONSENT_REQUEST_T;

#[repr(C)]
#[derive(PartialEq, Default)]
pub struct ConsentRequestT {
    pub arg_hash: [u8; 32],
    pub canister_id: [u8; CANISTER_MAX_LEN],
    pub canister_id_len: u16,
    pub ingress_expiry: u64,
    pub method_name: [u8; METHOD_MAX_LEN],
    pub method_name_len: u16,
    // pub request_type: [u8; REQUEST_MAX_LEN],
    // pub request_type_len: u16,
    pub sender: [u8; SENDER_MAX_LEN],
    pub sender_len: u16,
    // pub nonce: [u8; NONCE_MAX_LEN],
    // pub has_nonce: bool,
    pub request_id: [u8; 32],
}

// This converts from ConsentMsgRequest to ConsentRequestT
// also it assigns the inner args and method name of the candid
// encoded icrc21_consent_message_request
impl ConsentRequestT {
    pub fn reset(&mut self) {
        self.arg_hash.iter_mut().for_each(|x| *x = 0);
        self.canister_id.iter_mut().for_each(|x| *x = 0);
        self.method_name.iter_mut().for_each(|x| *x = 0);
        self.sender.iter_mut().for_each(|x| *x = 0);
        self.request_id.iter_mut().for_each(|x| *x = 0);
        self.canister_id_len = 0;
        self.sender_len = 0;
        self.method_name_len = 0;
        self.ingress_expiry = 0;
    }

    #[inline(never)]
    fn fill_from(&mut self, request: &ConsentMsgRequest<'_>) -> Result<(), ParserError> {
        check_canary();

        // Compute and store request_id
        let request_id = request.request_id();
        // let request_id = [0u8; 32];
        self.request_id.copy_from_slice(&request_id);

        // Compute arg_hash
        // remember this is the inner hash
        let Ok(icrc21) = request.arg().icrc21_msg_request() else {
            return Err(ParserError::InvalidConsentMsg);
        };

        let arg = icrc21.arg()?;

        let hash = hash_blob(arg);
        self.arg_hash.copy_from_slice(&hash);

        // Copy method_name
        // the one encoded in the inner args
        let method = icrc21.method()?;
        if method.len() > METHOD_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }
        self.method_name[..method.len()].copy_from_slice(method.as_bytes());
        self.method_name_len = method.len() as u16;

        // Copy canister_id
        if request.canister_id.len() > CANISTER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.canister_id[..request.canister_id.len()].copy_from_slice(request.canister_id);
        self.canister_id_len = request.canister_id.len() as u16;

        // Copy request_type
        // if request.request_type.len() > REQUEST_MAX_LEN {
        //     return Err(ParserError::ValueOutOfRange);
        // }
        // self.request_type[..request.request_type.len()]
        //     .copy_from_slice(request.request_type.as_bytes());
        // self.request_type_len = request.request_type.len() as u16;

        // Copy sender
        if request.sender.len() > SENDER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }
        self.sender[..request.sender.len()].copy_from_slice(request.sender);
        self.sender_len = request.sender.len() as u16;

        // Copy nonce if present
        // if let Some(nonce) = request.nonce {
        //     if nonce.len() > NONCE_MAX_LEN {
        //         return Err(ParserError::ValueOutOfRange);
        //     }
        //     self.nonce[..nonce.len()].copy_from_slice(nonce);
        //     self.has_nonce = true;
        // }

        Ok(())
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_parse_consent_request(data: *const u8, data_len: u16) -> u32 {
    if data.is_null() {
        return ParserError::NoData as u32;
    }

    let msg = std::slice::from_raw_parts(data, data_len as usize);

    // Create a MaybeUninit instance for consent request
    let mut request = MaybeUninit::<ConsentMsgRequest>::uninit();

    // Call from_bytes_into and handle the result
    match ConsentMsgRequest::from_bytes_into(msg, &mut request) {
        Ok(_) => {
            // Get the initialized CallRequest
            let request = request.assume_init_ref();

            // Fill canister_call_t fields from ConsentMsgRequest
            // NOTE: The method name and args of this types are not
            // assign directly, we assign the inner method and arg
            // of the candid encoded icrc21_consent_message_request
            // and also store the request_id
            // for later use

            if let Err(e) = fill_request(request) {
                return e as u32;
            }

            // Indicate consent request was parsed correctly
            CONSENT_REQUEST_T.1 = true;

            ParserError::Ok as u32
        }
        Err(_) => ParserError::InvalidConsentMsg as u32,
    }
}

#[inline(never)]
fn fill_request(request: &ConsentMsgRequest<'_>) -> Result<(), ParserError> {
    unsafe {
        if CONSENT_REQUEST_T.1 {
            return Err(ParserError::InvalidConsentMsg);
        }

        let consent_request = CONSENT_REQUEST_T.0.assume_init_mut();

        // Update our consent request
        consent_request.fill_from(request)?;
    }

    Ok(())
}
