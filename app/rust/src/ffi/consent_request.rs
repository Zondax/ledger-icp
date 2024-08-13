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
    error::ParserError,
    utils::{compress_leb128, hash_blob, hash_str},
    FromBytes,
};

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
}

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
        };

        // Compute arg_hash
        result.arg_hash = hash_blob(request.arg.raw_data());

        // Copy canister_id
        if request.canister_id.len() > 29 {
            return Err(ParserError::ValueOutOfRange);
        }
        result.canister_id[..request.canister_id.len()].copy_from_slice(request.canister_id);
        result.canister_id_len = request.canister_id.len() as u16;

        // Copy method_name
        if request.method_name.len() > 50 {
            return Err(ParserError::ValueOutOfRange);
        }
        result.method_name[..request.method_name.len()]
            .copy_from_slice(request.method_name.as_bytes());
        result.method_name_len = request.method_name.len() as u16;

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

impl consent_request_t {
    pub fn request_id(&self) -> [u8; 32] {
        const MAX_FIELDS: usize = 7;
        const FIELDS: [&str; MAX_FIELDS] = [
            "request_type",
            "sender",
            "ingress_expiry",
            "canister_id",
            "method_name",
            "arg",
            "nonce",
        ];

        let mut field_hashes = [[0u8; 64]; MAX_FIELDS];
        let mut field_count = 0;
        let max_fields = if self.nonce_len > 0 {
            MAX_FIELDS
        } else {
            MAX_FIELDS - 1
        };

        for (idx, key) in FIELDS.iter().enumerate().take(max_fields) {
            let key_hash = hash_str(key);

            let value_hash = match idx {
                0 => hash_blob(&self.request_type[..self.request_type_len as usize]),
                1 => hash_blob(&self.sender[..self.sender_len as usize]),
                2 => {
                    let mut buf = [0u8; 10];
                    let leb = compress_leb128(self.ingress_expiry, &mut buf);
                    hash_blob(leb)
                }
                3 => hash_blob(&self.canister_id[..self.canister_id_len as usize]),
                4 => hash_blob(&self.method_name[..self.method_name_len as usize]),
                5 => self.arg_hash, // Use arg_hash directly
                6 => {
                    if self.nonce_len > 0 {
                        hash_blob(&self.nonce[..self.nonce_len as usize])
                    } else {
                        break;
                    }
                }
                _ => unreachable!(),
            };

            field_hashes[field_count][..32].copy_from_slice(&key_hash);
            field_hashes[field_count][32..].copy_from_slice(&value_hash);
            field_count += 1;
        }

        field_hashes[..field_count].sort_unstable();

        // omit Nonce if no present
        let mut concatenated = [0u8; MAX_FIELDS * 64];
        for (i, hash) in field_hashes[..field_count].iter().enumerate() {
            concatenated[i * 64..(i + 1) * 64].copy_from_slice(hash);
        }
        hash_blob(&concatenated[..field_count * 64])
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

#[cfg(test)]
mod c_consent_test {
    use super::*;

    const REQUEST: &str = "d9d9f7a167636f6e74656e74a763617267586b4449444c076d7b6c01d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d026e036c02efcee7800401c4fbf2db05046c03d6fca70200e1edeb4a7184f7fee80a0501060c4449444c00017104746f626905677265657402656e01011e0003006b63616e69737465725f69644a00000000006000fd01016e696e67726573735f6578706972791bf0edf1e9943528006b6d6574686f645f6e616d6578246963726332315f63616e69737465725f63616c6c5f636f6e73656e745f6d657373616765656e6f6e636550a3788c1805553fb69b20f08e87e23b136c726571756573745f747970656463616c6c6673656e6465724104";

    #[test]
    fn ffi_msg_request() {
        let data = hex::decode(REQUEST).unwrap();
        let (_, msg_req) = ConsentMsgRequest::parse(&data).unwrap();
        let request_id = hex::encode(msg_req.request_id());

        let c_request = consent_request_t::try_from(msg_req).unwrap();
        let c_request_id = hex::encode(c_request.request_id());

        assert_eq!(c_request_id, request_id);
    }

    #[test]
    fn ffi_msg_request_nonce_none() {
        let data = hex::decode(REQUEST).unwrap();
        let (_, mut msg_req) = ConsentMsgRequest::parse(&data).unwrap();
        // set nonce to None
        msg_req.nonce = None;
        let request_id = hex::encode(msg_req.request_id());

        let c_request = consent_request_t::try_from(msg_req).unwrap();
        let c_request_id = hex::encode(c_request.request_id());

        assert_eq!(c_request_id, request_id);
    }
}
