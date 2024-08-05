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

use crate::{call_request::CallRequest, error::ParserError, FromBytes};

use core::mem::MaybeUninit;
use sha2::{Digest, Sha256};

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(PartialEq)]
pub struct canister_call_t {
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
}

#[no_mangle]
pub unsafe extern "C" fn parse_canister_call_request(
    data: *const u8,
    data_len: u16,
    out_request: *mut canister_call_t,
) -> u32 {
    if data.is_null() || out_request.is_null() {
        return ParserError::NoData as u32;
    }

    let msg = std::slice::from_raw_parts(data, data_len as usize);

    // Create a MaybeUninit instance for CallRequest
    let mut call_request = MaybeUninit::<CallRequest>::uninit();

    // Call from_bytes_into and handle the result
    match CallRequest::from_bytes_into(msg, &mut call_request) {
        Ok(_) => {
            let request = call_request.assume_init();

            // Fill canister_call_t fields from CallRequest
            let out = &mut *out_request;

            let mut hasher = Sha256::new();
            hasher.update(request.arg);
            let result = hasher.finalize();

            out.arg_hash.copy_from_slice(result.as_slice());
            out.canister_id.copy_from_slice(request.canister_id);
            out.canister_id_len = request.canister_id.len() as u16;
            out.ingress_expiry = request.ingress_expiry;
            out.method_name
                .copy_from_slice(request.method_name.as_bytes());
            out.method_name_len = request.method_name.len() as u16;
            out.request_type
                .copy_from_slice(request.request_type.as_bytes());
            out.request_type_len = request.request_type.len() as u16;
            out.sender.copy_from_slice(request.sender);
            out.sender_len = request.sender.len() as u16;

            ParserError::Ok as u32
        }
        Err(_) => ParserError::InvalidCallRequest as u32,
    }
}
