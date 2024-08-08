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

use crate::{call_request::ConsentMsgRequest, error::ParserError, FromBytes};

use core::mem::MaybeUninit;
use sha2::{Digest, Sha256};

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
    // This field is not part of the original
    // struct, it is just a place holder for the
    // independent hash of this data, and used during
    // certificate verification.
    pub request_id: [u8; 32],
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

            // Get the request_id from the parsed data, this is use
            // for certificate validation.
            let request_id = request.request_id();

            let icrc_request = request.arg().icrc21_msg_request();

            // Fill canister_call_t fields from ConsentMsgRequest
            let out = &mut *out_request;

            let mut hasher = Sha256::new();
            hasher.update(icrc_request.arg());
            let result = hasher.finalize();

            out.arg_hash.copy_from_slice(result.as_slice());
            out.canister_id.copy_from_slice(request.canister_id);
            out.canister_id_len = request.canister_id.len() as u16;
            out.ingress_expiry = request.ingress_expiry;

            // use icrc21_message_request method and args
            out.method_name
                .copy_from_slice(icrc_request.method().as_bytes());

            out.method_name_len = icrc_request.method().len() as u16;
            out.request_type
                .copy_from_slice(request.request_type.as_bytes());
            out.request_type_len = request.request_type.len() as u16;
            out.sender.copy_from_slice(request.sender);
            out.sender_len = request.sender.len() as u16;
            out.nonce.copy_from_slice(request.nonce);
            out.nonce_len = request.nonce.len() as u16;
            out.request_id.copy_from_slice(request_id.as_ref());

            ParserError::Ok as u32
        }
        Err(_) => ParserError::InvalidConsentMsg as u32,
    }
}
