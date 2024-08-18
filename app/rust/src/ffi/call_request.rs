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

use crate::{call_request::CallRequest, constants::*, error::ParserError, FromBytes};

use core::mem::MaybeUninit;
use sha2::{Digest, Sha256};

use super::resources::CALL_REQUEST_T;

#[repr(C)]
#[derive(PartialEq, Default)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct CanisterCallT {
    pub arg_hash: [u8; 32],
    pub canister_id: [u8; CANISTER_MAX_LEN],
    pub canister_id_len: u16,
    pub ingress_expiry: u64,
    pub method_name: [u8; METHOD_MAX_LEN],
    pub method_name_len: u16,
    pub request_type: [u8; REQUEST_MAX_LEN],
    pub request_type_len: u16,
    pub sender: [u8; SENDER_MAX_LEN],
    pub sender_len: u16,
    pub nonce: [u8; NONCE_MAX_LEN],
    pub has_nonce: bool,

    // The hash of this call request
    // which is going to be signed
    pub hash: [u8; 32],
}

impl CanisterCallT {
    fn fill_from(&mut self, request: &CallRequest<'_>) -> Result<(), ParserError> {
        crate::zlog("CanisterCallT::fill_from\x00");

        // Compute the call request hash
        // to be signed
        let hash = request.digest();
        self.hash.copy_from_slice(&hash);

        // Compute arg hash
        let mut hasher = Sha256::new();
        hasher.update(request.arg);
        let arg_hash = hasher.finalize();

        self.arg_hash.copy_from_slice(arg_hash.as_slice());

        if request.canister_id().len() > CANISTER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.canister_id.copy_from_slice(request.canister_id);
        self.canister_id_len = request.canister_id.len() as u16;
        self.ingress_expiry = request.ingress_expiry;

        if request.method_name.len() > METHOD_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.method_name[..request.method_name.len()]
            .copy_from_slice(request.method_name.as_bytes());
        self.method_name_len = request.method_name.len() as u16;

        if request.request_type.len() > REQUEST_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.request_type[..request.request_type.as_bytes().len()]
            .copy_from_slice(request.request_type.as_bytes());
        self.request_type_len = request.request_type.as_bytes().len() as u16;

        if request.sender.len() > SENDER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.sender[..request.sender.len()].copy_from_slice(request.sender);
        self.sender_len = request.sender.len() as u16;

        if let Some(nonce) = request.nonce {
            self.has_nonce = true;
            self.nonce.copy_from_slice(nonce);
        }
        crate::zlog("CanisterCallT::fill_from: done!\x00");

        Ok(())
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_parse_canister_call_request(data: *const u8, data_len: u16) -> u32 {
    if data.is_null() {
        return ParserError::NoData as u32;
    }

    let msg = std::slice::from_raw_parts(data, data_len as usize);

    // Create a MaybeUninit instance for CallRequest
    let mut call_request = MaybeUninit::<CallRequest>::uninit();

    // Call from_bytes_into and handle the result
    match CallRequest::from_bytes_into(msg, &mut call_request) {
        Ok(_) => {
            let request = call_request.assume_init();

            // Global must be empty at this point
            if CALL_REQUEST_T.is_some() {
                return ParserError::InvalidConsentMsg as u32;
            }
            let mut call_request = CanisterCallT::default();
            if let Err(e) = call_request.fill_from(&request) {
                return e as u32;
            }

            // Update our consent request
            CALL_REQUEST_T.replace(call_request);

            ParserError::Ok as u32
        }
        Err(_) => ParserError::InvalidCallRequest as u32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_get_signing_hash(data: *mut [u8; 32]) {
    let hash = unsafe { &mut *data };

    if let Some(call) = CALL_REQUEST_T.as_ref() {
        hash.copy_from_slice(&call.hash);
    }
}
