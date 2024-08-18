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
    constants::BLS_PUBLIC_KEY_SIZE, error::ParserError, Certificate, HashTree, LookupResult,
};

use std::cmp::PartialEq;

use super::{
    call_request::CanisterCallT,
    consent_request::ConsentRequestT,
    resources::{CALL_REQUEST_T, CERTIFICATE, CONSENT_REQUEST_T},
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
pub unsafe extern "C" fn rs_verify_certificate(
    certificate: *const u8,
    certificate_len: u16,
    root_key: *const u8,
) -> u32 {
    crate::zlog("rs_parser_verify_certificate\x00");
    if certificate.is_null() || root_key.is_null() {
        crate::zlog("no_cert/no_key\x00");
        return ParserError::NoData as u32;
    }

    let Some(call_request) = CALL_REQUEST_T.as_ref() else {
        crate::zlog("no_call_request\x00");
        return ParserError::NoData as u32;
    };
    let Some(consent_request) = CONSENT_REQUEST_T.as_ref() else {
        crate::zlog("no_consent_request\x00");
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

    if CERTIFICATE.is_some() {
        crate::zlog("certificate already present****\x00");
        return ParserError::InvalidCertificate as u32;
    }

    let Ok(cert) = Certificate::parse(data) else {
        return ParserError::InvalidCertificate as u32;
    };

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

    // Verify ingress_expiry aginst certificate timestamp
    if !cert.verify_time(call_request.ingress_expiry) {
        crate::zlog("ingress_expiry mismatch****\x00");
        return ParserError::InvalidCertificate as u32;
    }

    CERTIFICATE.replace(cert);

    // Now store the certificate back in memory for ui usage?
    ParserError::Ok as u32
}
