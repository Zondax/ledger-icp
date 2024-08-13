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
    constants::BLS_PUBLIC_KEY_SIZE, error::ParserError, Certificate, FromBytes, HashTree,
    LookupResult,
};

use core::mem::MaybeUninit;
use std::cmp::PartialEq;

use super::{call_request::canister_call_t, consent_request::consent_request_t};

impl PartialEq<consent_request_t> for canister_call_t {
    fn eq(&self, other: &consent_request_t) -> bool {
        self.arg_hash == other.arg_hash
            && self.canister_id[..self.canister_id_len as usize]
                == other.canister_id[..other.canister_id_len as usize]
            && self.method_name[..self.method_name_len as usize]
                == other.method_name[..other.method_name_len as usize]
            && self.sender[..self.sender_len as usize] == other.sender[..other.sender_len as usize]
    }
}

// This allows consent_request_t == canister_call_t to work as well
impl PartialEq<canister_call_t> for consent_request_t {
    fn eq(&self, other: &canister_call_t) -> bool {
        other == self
    }
}

#[no_mangle]
pub unsafe extern "C" fn parser_verify_certificate(
    certificate: *const u8,
    certificate_len: u16,
    root_key: *const u8,
    call_request: *const canister_call_t,
    consent_request: *const consent_request_t,
) -> u32 {
    if call_request.is_null()
        || consent_request.is_null()
        || certificate.is_null()
        || root_key.is_null()
    {
        return ParserError::NoData as u32;
    }

    let call_request = &*call_request;
    let consent_request = &*consent_request;

    // This call the PartialEq implementation
    // for canister_call_t and consent_request_t
    // which ensures canister_id, method and args are the same in both
    if call_request != consent_request {
        return ParserError::InvalidCertificate as u32;
    }

    let data = core::slice::from_raw_parts(certificate, certificate_len as usize);
    let root_key = core::slice::from_raw_parts(root_key, BLS_PUBLIC_KEY_SIZE);

    let mut cert = MaybeUninit::uninit();
    let Ok(_) = Certificate::from_bytes_into(data, &mut cert) else {
        return ParserError::InvalidCertificate as u32;
    };

    let cert = cert.assume_init();

    match cert.verify(root_key) {
        Ok(false) => return ParserError::InvalidCertificate as u32,
        Err(e) => return e as u32,
        _ => {}
    }

    let tree = cert.tree();
    let request_id = consent_request.request_id;

    // Certificate tree must contain a node labeled with the request_id computed
    // from the consent_msg_request, this ensures that the passed data referes to
    // the provided certificate
    let Ok(LookupResult::Found(_)) = HashTree::lookup_path(&request_id[..].into(), tree) else {
        return ParserError::InvalidCertificate as u32;
    };

    // Now store the certificate back in memory for ui usage?
    ParserError::Ok as u32
}
