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

use super::resources::get_call_request_memory;

#[repr(C)]
#[derive(PartialEq, Default)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct CanisterCallT {
    pub arg_hash: [u8; ARG_HASH_LEN],
    pub canister_id: [u8; CANISTER_MAX_LEN],
    pub canister_id_len: u16,
    pub ingress_expiry: u64,
    pub method_name: [u8; METHOD_MAX_LEN],
    pub method_name_len: u16,
    pub sender: [u8; SENDER_MAX_LEN],
    pub sender_len: u16,

    // The hash of this call request
    // which is going to be signed
    pub hash: [u8; SHA256_DIGEST_LENGTH],
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
    #[inline(never)]
    fn fill_from(&mut self, request: &CallRequest<'_>) -> Result<(), ParserError> {
        check_canary();
        crate::zlog("CanisterCallT::fill_from\x00");

        // Compute the call request hash
        // to be signed
        let hash = request.digest();
        self.hash.copy_from_slice(&hash);

        // Compute arg hash
        let mut hasher = Sha256::new();
        hasher.update(request.arg().raw_data());
        let arg_hash = hasher.finalize();

        self.arg_hash.copy_from_slice(arg_hash.as_slice());

        let canister_id = request.canister_id();
        if canister_id.len() > CANISTER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        // Copy into the prefix: canister ids are variable length and
        // copy_from_slice requires both sides to match exactly.
        self.canister_id[..canister_id.len()].copy_from_slice(canister_id);
        self.canister_id_len = canister_id.len() as u16;
        self.ingress_expiry = request.ingress_expiry();

        if request.method_name().len() > METHOD_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.method_name[..request.method_name().len()]
            .copy_from_slice(request.method_name().as_bytes());
        self.method_name_len = request.method_name().len() as u16;

        if request.sender().len() > SENDER_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        self.sender[..request.sender().len()].copy_from_slice(request.sender());
        self.sender_len = request.sender().len() as u16;

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
        Ok(rem) => {
            if !rem.is_empty() {
                return ParserError::InvalidCallRequest as u32;
            }
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
    // Create a properly aligned CanisterCallT on the stack. Zero the whole
    // allocation rather than using Default: repr(C) leaves 4 bytes of padding
    // before ingress_expiry, and fill_to() copies the struct byte-wise into
    // NVM, so field-only initialization would persist uninitialized stack
    // bytes to flash.
    let mut call_request: CanisterCallT = unsafe { MaybeUninit::zeroed().assume_init() };

    // Fill it with data from the request
    call_request.fill_from(request)?;

    // Now serialize it to bytes for storage
    let mut serialized = [0; core::mem::size_of::<CanisterCallT>()];
    call_request.fill_to(&mut serialized)?;

    unsafe {
        super::resources::write_call_request(&serialized)
            .map_err(|_| ParserError::UnexpectedError)?;

        // Verify the write succeeded by reading back and validating
        // Use a safe copy to avoid potential alignment issues
        let stored_memory = super::resources::get_call_request_memory();
        if stored_memory.len() != core::mem::size_of::<CanisterCallT>() {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        let mut stored_call = CanisterCallT::default();
        core::ptr::copy_nonoverlapping(
            stored_memory.as_ptr(),
            &mut stored_call as *mut CanisterCallT as *mut u8,
            core::mem::size_of::<CanisterCallT>(),
        );
        stored_call.validate()?;
    }

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_get_signing_hash(data: *mut [u8; 32]) {
    let hash = unsafe { &mut *data };

    let Ok(call) = CanisterCallT::from_bytes(get_call_request_memory()) else {
        return;
    };

    hash.copy_from_slice(&call.hash);
}

#[cfg(test)]
mod test {
    use super::*;

    // ICRC-2 approve call whose canister_id is the 10-byte 00000000000000020101.
    const REQUEST: &str = "d9d9f7a167636f6e74656e74a76361726758684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b18072a6f7894d0006b6d6574686f645f6e616d656d69637263325f617070726f7665656e6f6e6365506b99f1c2338b4543152aae206d5286726c726571756573745f747970656463616c6c6673656e646572581d052c5f6f270fc4a3a882a8075732cba90ad4bd25d30bd2cf7b0bfe7c02";

    // The same call retargeted at the management canister (aaaaa-aa), whose
    // principal is the empty blob, so canister_id is CBOR bytes(0) instead of
    // bytes(10). Any length other than CANISTER_MAX_LEN used to abort here.
    const REQUEST_EMPTY_CANISTER_ID: &str = "d9d9f7a167636f6e74656e74a76361726758684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101006b63616e69737465725f6964406e696e67726573735f6578706972791b18072a6f7894d0006b6d6574686f645f6e616d656d69637263325f617070726f7665656e6f6e6365506b99f1c2338b4543152aae206d5286726c726571756573745f747970656463616c6c6673656e646572581d052c5f6f270fc4a3a882a8075732cba90ad4bd25d30bd2cf7b0bfe7c02";

    #[test]
    fn fill_from_accepts_canister_id_shorter_than_max() {
        let data = hex::decode(REQUEST_EMPTY_CANISTER_ID).unwrap();
        let call_request = CallRequest::from_bytes(&data).unwrap();
        assert!(call_request.canister_id().is_empty());

        let mut call = CanisterCallT::default();
        call.fill_from(&call_request).unwrap();

        assert_eq!(call.canister_id_len, 0);
        assert_eq!(call.canister_id, [0u8; CANISTER_MAX_LEN]);
    }

    #[test]
    fn fill_from_keeps_full_length_canister_id() {
        let data = hex::decode(REQUEST).unwrap();
        let call_request = CallRequest::from_bytes(&data).unwrap();

        let mut call = CanisterCallT::default();
        call.fill_from(&call_request).unwrap();

        assert_eq!(call.canister_id_len as usize, CANISTER_MAX_LEN);
        assert_eq!(
            hex::encode(call.canister_id),
            "00000000000000020101"
        );
    }
}
