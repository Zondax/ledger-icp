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
    call_request::CallRequest, check_canary, constants::*, error::ParserError,
    utils::ByteSerializable, FromBytes,
};

use core::mem::{size_of, MaybeUninit};
use sha2::{Digest, Sha256};

use super::resources::MEMORY_CALL_REQUEST;

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
    // pub request_type: [u8; REQUEST_MAX_LEN],
    // pub request_type_len: u16,
    pub sender: [u8; SENDER_MAX_LEN],
    pub sender_len: u16,
    // pub nonce: [u8; NONCE_MAX_LEN],
    // pub has_nonce: bool,

    // The hash of this call request
    // which is going to be signed
    pub hash: [u8; 32],
}

impl ByteSerializable for CanisterCallT {
    #[inline(never)]
    fn fill_to(&self, output: &mut [u8]) -> Result<(), ParserError> {
        if output.len() != size_of::<Self>() {
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

impl CanisterCallT {
    fn fill_from(&mut self, request: &CallRequest<'_>) -> Result<(), ParserError> {
        check_canary();
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

        if request.sender.len() > SENDER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.sender[..request.sender.len()].copy_from_slice(request.sender);
        self.sender_len = request.sender.len() as u16;

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

            if let Err(e) = fill_request(&request) {
                return e as u32;
            }

            ParserError::Ok as u32
        }
        Err(_) => ParserError::InvalidCallRequest as u32,
    }
}

#[inline(never)]
fn fill_request(request: &CallRequest<'_>) -> Result<(), ParserError> {
    unsafe {
        // let consent_request = CONSENT_REQUEST_T.0.assume_init_mut();
        let mut consent_request = CanisterCallT::default();

        // Update our consent request
        consent_request.fill_from(request)?;

        let mut serialized = [0; core::mem::size_of::<CanisterCallT>()];
        consent_request.fill_to(&mut serialized)?;

        MEMORY_CALL_REQUEST
            .write(0, &serialized)
            .map_err(|_| ParserError::UnexpectedError)?;

        let consent2 = CanisterCallT::from_bytes(&**MEMORY_CALL_REQUEST)?;
        consent2.validate()?;

        // Indicate consent request was parsed correctly
    }

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_get_signing_hash(data: *mut [u8; 32]) {
    let hash = unsafe { &mut *data };

    let Ok(call) = CanisterCallT::from_bytes(&**MEMORY_CALL_REQUEST) else {
        return;
    };

    hash.copy_from_slice(&call.hash);
}
