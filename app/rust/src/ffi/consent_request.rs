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

use crate::{call_request::ConsentMsgRequest, error::ParserError, utils::hash_blob, FromBytes};

use core::mem::MaybeUninit;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(PartialEq)]
pub struct consent_request_t {
    pub arg_hash: [u8; 32],
    pub canister_id: [u8; 29],
    pub canister_id_len: u16,
    pub ingress_expiry: u64,
    pub method_name: [u8; 50],
    pub method_name_len: u16,
    pub request_type: [u8; 50],
    pub request_type_len: u16,
    pub sender: [u8; 50],
    pub sender_len: u16,
    pub nonce: [u8; 50],
    pub nonce_len: u16,

    pub request_id: [u8; 32],
}

// This converts from ConsentMsgRequest to consent_request_t
// also it assigns the inner args and method name of the candid
// encoded icrc21_consent_message_request
impl TryFrom<ConsentMsgRequest<'_>> for consent_request_t {
    type Error = ParserError;

    fn try_from(request: ConsentMsgRequest<'_>) -> Result<Self, Self::Error> {
        let mut result = consent_request_t {
            arg_hash: [0; 32],
            canister_id: [0; 29],
            canister_id_len: 0,
            ingress_expiry: request.ingress_expiry,
            method_name: [0; 50],
            method_name_len: 0,
            request_type: [0; 50],
            request_type_len: 0,
            sender: [0; 50],
            sender_len: 0,
            nonce: [0; 50],
            nonce_len: 0,
            request_id: [0; 32],
        };

        // Compute and store request_id
        let request_id = request.request_id();
        result.request_id.copy_from_slice(&request_id);

        // Compute arg_hash
        // remember this is the inner hash
        let icrc21 = request.arg().icrc21_msg_request();
        result.arg_hash = hash_blob(icrc21.arg());

        // Copy canister_id
        if request.canister_id.len() > 29 {
            return Err(ParserError::ValueOutOfRange);
        }
        result.canister_id[..request.canister_id.len()].copy_from_slice(request.canister_id);
        result.canister_id_len = request.canister_id.len() as u16;

        // Copy method_name
        // the one encoded in the inner args
        if request.method_name.len() > 50 {
            return Err(ParserError::ValueOutOfRange);
        }
        result.method_name[..icrc21.method().len()].copy_from_slice(icrc21.method().as_bytes());
        result.method_name_len = icrc21.method().len() as u16;

        // Copy request_type
        if request.request_type.len() > 50 {
            return Err(ParserError::ValueOutOfRange);
        }
        result.request_type[..request.request_type.len()]
            .copy_from_slice(request.request_type.as_bytes());
        result.request_type_len = request.request_type.len() as u16;

        // Copy sender
        if request.sender.len() > 50 {
            return Err(ParserError::ValueOutOfRange);
        }
        result.sender[..request.sender.len()].copy_from_slice(request.sender);
        result.sender_len = request.sender.len() as u16;

        // Copy nonce if present
        if let Some(nonce) = request.nonce {
            if nonce.len() > 50 {
                return Err(ParserError::ValueOutOfRange);
            }
            result.nonce[..nonce.len()].copy_from_slice(nonce);
            result.nonce_len = nonce.len() as u16;
        }

        Ok(result)
    }
}

#[no_mangle]
pub unsafe extern "C" fn parse_consent_request(
    data: *const u8,
    data_len: u16,
    out_request: *mut consent_request_t,
) -> u32 {
    if data.is_null() || out_request.is_null() {
        return ParserError::NoData as u32;
    }

    let msg = std::slice::from_raw_parts(data, data_len as usize);

    // Create a MaybeUninit instance for consent request
    let mut call_request = MaybeUninit::<ConsentMsgRequest>::uninit();

    // Call from_bytes_into and handle the result
    match ConsentMsgRequest::from_bytes_into(msg, &mut call_request) {
        Ok(_) => {
            // Get the initialized CallRequest
            let request = call_request.assume_init();

            // Fill canister_call_t fields from ConsentMsgRequest
            // NOTE: The method name and args of this types are not
            // assign directly, we assign the inner method and arg
            // of the candid encoded icrc21_consent_message_request
            // and also store the request_id
            // for later use
            let out = &mut *out_request;

            let Ok(c_request) = consent_request_t::try_from(request) else {
                return ParserError::InvalidConsentMsg as u32;
            };

            *out = c_request;

            ParserError::Ok as u32
        }
        Err(_) => ParserError::InvalidConsentMsg as u32,
    }
}
