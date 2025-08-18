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
    call_request::ConsentMsgRequest,
    check_canary,
    constants::*,
    error::ParserError,
    utils::{hash_blob, ByteSerializable},
    FromBytes,
};

use core::mem::{size_of, MaybeUninit};

use super::resources::get_consent_request_memory;

#[repr(C)]
#[derive(PartialEq, Default)]
pub struct ConsentRequestT {
    pub arg_hash: [u8; ARG_HASH_LEN],
    pub canister_id: [u8; CANISTER_MAX_LEN],
    pub canister_id_len: u16,
    pub ingress_expiry: u64,
    pub method_name: [u8; METHOD_MAX_LEN],
    pub method_name_len: u16,
    pub sender: [u8; SENDER_MAX_LEN],
    pub sender_len: u16,
    // This request_id is used
    // to lookup for the reply field
    // in a certificate, this ensures that
    // the consent_request being processed refers to the provided
    // BLS certificate
    pub request_id: [u8; SHA256_DIGEST_LENGTH],
}

impl ByteSerializable for ConsentRequestT {
    #[inline(never)]
    fn fill_to(&self, output: &mut [u8]) -> Result<(), ParserError> {
        if output.len() != core::mem::size_of::<Self>() {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                output.as_mut_ptr(),
                core::mem::size_of::<Self>(),
            );
        }

        Ok(())
    }

    #[inline(never)]
    fn from_bytes(input: &[u8]) -> Result<&Self, ParserError> {
        if input.len() != size_of::<Self>() {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        let result = unsafe { &*(input.as_ptr() as *const Self) };
        result.validate()?;
        Ok(result)
    }

    #[inline(never)]
    fn validate(&self) -> Result<(), ParserError> {
        if self.canister_id_len as usize > CANISTER_MAX_LEN
            || self.method_name_len as usize > METHOD_MAX_LEN
            || self.sender_len as usize > SENDER_MAX_LEN
        {
            return Err(ParserError::ValueOutOfRange);
        }
        Ok(())
    }
}

// This converts from ConsentMsgRequest to ConsentRequestT
// also it assigns the inner args and method name of the candid
// encoded icrc21_consent_message_request
impl ConsentRequestT {
    #[inline(never)]
    fn fill_from(&mut self, request: &ConsentMsgRequest<'_>) -> Result<(), ParserError> {
        check_canary();

        crate::zlog("ConsentRequestT::fill_from\x00");

        // Compute and store request_id
        let request_id = request.request_id();

        self.request_id.copy_from_slice(&request_id);

        // Compute arg_hash
        // remember this is the inner hash
        let Ok(icrc21) = request.icrc21_msg_request() else {
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
        let canister_id = request.canister_id();
        if canister_id.len() > CANISTER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.canister_id[..canister_id.len()].copy_from_slice(canister_id);
        self.canister_id_len = canister_id.len() as u16;

        // Copy sender
        let sender = request.sender();
        if sender.len() > SENDER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }
        self.sender[..sender.len()].copy_from_slice(sender);
        self.sender_len = sender.len() as u16;

        Ok(())
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_parse_consent_request(data: *const u8, data_len: u16) -> u32 {
    crate::zlog("rs_parse_consent_request\x00");

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

            crate::zlog("consent_request::ok\x00");

            ParserError::Ok as u32
        }
        Err(_) => ParserError::InvalidConsentMsg as u32,
    }
}

#[inline(never)]
fn fill_request(request: &ConsentMsgRequest<'_>) -> Result<(), ParserError> {
    crate::zlog("consent_request::fill\x00");
    let mut serialized = [0; core::mem::size_of::<ConsentRequestT>()];
    unsafe {
        {
            // Lets transmute the array in order to reuse serialized memory
            // saving a bunch of stack
            let consent_request = &mut *(serialized.as_mut_ptr() as *mut ConsentRequestT);

            // Update our consent request
            consent_request.fill_from(request)?;

            super::resources::write_consent_request(&serialized)
                .map_err(|_| ParserError::UnexpectedError)?;
        }

        let consent2 = ConsentRequestT::from_bytes(get_consent_request_memory())?;
        consent2.validate()?;
    }

    Ok(())
}
