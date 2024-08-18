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
    certificate_from_state, constants::BLS_PUBLIC_KEY_SIZE, error::ParserError, Certificate,
    FromBytes, HashTree, LookupResult,
};

use std::cmp::PartialEq;

use super::{
    call_request::CanisterCallT,
    consent_request::ConsentRequestT,
    context::parsed_obj_t,
    resources::{CALL_REQUEST_T, CONSENT_REQUEST_T},
};

impl PartialEq<ConsentRequestT> for CanisterCallT {
    fn eq(&self, other: &ConsentRequestT) -> bool {
        self.arg_hash == other.arg_hash
            && self.canister_id[..self.canister_id_len as usize]
                == other.canister_id[..other.canister_id_len as usize]
            && self.method_name[..self.method_name_len as usize]
                == other.method_name[..other.method_name_len as usize]
            && self.sender[..self.sender_len as usize] == other.sender[..other.sender_len as usize]
    }
}

// This allows consent_request_t == canister_call_t to work as well
impl PartialEq<CanisterCallT> for ConsentRequestT {
    fn eq(&self, other: &CanisterCallT) -> bool {
        other == self
    }
}

#[no_mangle]
pub unsafe extern "C" fn parser_verify_certificate(
    certificate: *const u8,
    certificate_len: u16,
    root_key: *const u8,
    parsed_cert: *mut parsed_obj_t,
) -> u32 {
    crate::zlog("parser_verify_certificate\x00");
    if certificate.is_null() || root_key.is_null() {
        return ParserError::NoData as u32;
    }

    let Some(call_request) = CALL_REQUEST_T.as_ref() else {
        return ParserError::NoData as u32;
    };
    let Some(consent_request) = CONSENT_REQUEST_T.as_ref() else {
        return ParserError::NoData as u32;
    };

    // This call the PartialEq implementation
    // for canister_call_t and consent_request_t
    // which ensures canister_id, method and args are the same in both
    if call_request != consent_request {
        crate::zlog("call_request != consent_request****\x00");
        return ParserError::InvalidCertificate as u32;
    }

    let data = core::slice::from_raw_parts(certificate, certificate_len as usize);
    let root_key = core::slice::from_raw_parts(root_key, BLS_PUBLIC_KEY_SIZE);

    let cert = certificate_from_state!(parsed_cert);

    let Ok(_) = Certificate::from_bytes_into(data, cert) else {
        return ParserError::InvalidCertificate as u32;
    };

    let cert = cert.assume_init();
    crate::zlog("cert_parsed****\x00");

    match cert.verify(root_key) {
        Ok(false) => return ParserError::InvalidCertificate as u32,
        Err(e) => return e as u32,
        _ => {}
    }
    crate::zlog("cert_verified****\x00");

    let tree = cert.tree();
    let request_id = consent_request.request_id;

    // Certificate tree must contain a node labeled with the request_id computed
    // from the consent_msg_request, this ensures that the passed data referes to
    // the provided certificate
    let Ok(LookupResult::Found(_)) = HashTree::lookup_path(&request_id[..].into(), tree) else {
        crate::zlog("request_id mismatch****\x00");
        return ParserError::InvalidCertificate as u32;
    };

    // Now store the certificate back in memory for ui usage?
    ParserError::Ok as u32
}
