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
    check_canary, constants::BLS_PUBLIC_KEY_SIZE, error::ParserError, Certificate, FromBytes,
    HashTree, LookupResult, Principal,
};

use core::mem::MaybeUninit;
use std::cmp::PartialEq;

use super::{
    c_api::device_principal,
    call_request::CanisterCallT,
    consent_request::ConsentRequestT,
    resources::{CALL_REQUEST_T, CERTIFICATE, CONSENT_REQUEST_T},
};

// This is use to check important fields in consent_msg_request and canister_call_request
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
    check_canary();
    if certificate.is_null() || root_key.is_null() {
        return ParserError::NoData as u32;
    }

    // Check values are set
    crate::zlog("call_request****\x00");
    let Some(call_request) = CALL_REQUEST_T.as_ref() else {
        return ParserError::NoData as u32;
    };

    crate::zlog("consent_request****\x00");
    let Some(consent_request) = CONSENT_REQUEST_T.as_ref() else {
        return ParserError::NoData as u32;
    };

    // This call the PartialEq implementation
    // for canister_call_t and consent_request_t
    // which ensures canister_id, method and args are the same in both
    if call_request != consent_request {
        crate::zlog("call != consent mistmatch\x00");
        return ParserError::InvalidCertificate as u32;
    }

    let data = core::slice::from_raw_parts(certificate, certificate_len as usize);
    let root_key = core::slice::from_raw_parts(root_key, BLS_PUBLIC_KEY_SIZE);

    if CERTIFICATE.is_some() {
        crate::zlog("certificate already present****\x00");
        return ParserError::InvalidCertificate as u32;
    }

    crate::zlog("parse_cert****\x00");
    let mut cert = MaybeUninit::uninit();
    let Ok(_) = Certificate::from_bytes_into(data, &mut cert) else {
        crate::zlog("Could not parse certificate****\x00");
        return ParserError::InvalidCertificate as u32;
    };

    let cert = unsafe { cert.assume_init() };

    match cert.verify(root_key) {
        Ok(false) => return ParserError::InvalidCertificate as u32,
        Err(e) => return e as u32,
        _ => {}
    }
    crate::zlog("cert_signature_verified****\x00");

    // Certificate tree must contain a node labeled with the request_id computed
    // from the consent_msg_request, this ensures that the passed data referes to
    // the provided certificate
    let Ok(LookupResult::Found(_)) =
        HashTree::lookup_path(&consent_request.request_id[..].into(), cert.tree())
    else {
        crate::zlog("request_id mismatch****\x00");
        return ParserError::InvalidCertificate as u32;
    };

    // Verify ingress_expiry aginst certificate timestamp
    if !cert.verify_time(call_request.ingress_expiry) {
        crate::zlog("ingress_expiry mismatch****\x00");
        return ParserError::InvalidCertificate as u32;
    }

    // Check sender identity
    let sender = &consent_request.sender[..consent_request.sender_len as usize];
    let device_principal = device_principal();

    let Ok(sender) = Principal::new(sender) else {
        return ParserError::InvalidCertificate as u32;
    };

    if !sender.is_default() && sender != device_principal {
        crate::zlog("sender_id mismatch****\x00");
        return ParserError::InvalidCertificate as u32;
    }

    // Check canister_id in request/consent is within allowed canister in the
    // certificate canister ranges
    // if let Some(ranges) = cert.canister_ranges() {
    //     if ranges.is_canister_in_range(
    //         &call_request.canister_id[..call_request.canister_id_len as usize],
    //     ) {
    //         crate::zlog("canister_id mismatch****\x00");
    //         return ParserError::InvalidCertificate as u32;
    //     }
    // }

    // Indicates certificate was valid
    CERTIFICATE.replace(cert);

    ParserError::Ok as u32
}
