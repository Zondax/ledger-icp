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
    check_canary,
    consent_message::msg_response::ConsentMessageResponse,
    constants::{BLS_PUBLIC_KEY_SIZE, DEFAULT_SENDER, REQUEST_STATUS_PATH},
    error::ParserError,
    Certificate, FromBytes, HashTree, LookupResult, Principal,
};

use core::mem::MaybeUninit;
use std::cmp::PartialEq;

use crate::utils::ByteSerializable;

use super::{
    c_api::device_principal,
    call_request::CanisterCallT,
    consent_request::ConsentRequestT,
    resources::{
        certificate_is_some, get_call_request_memory, get_consent_request_memory, set_certificate,
        set_ui,
    },
};

// Bind the call envelope to the reviewed consent envelope. Equality of
// `arg_hash`, `canister_id`, and `method_name` ensures the canister behaviour
// signed matches the consent the user reviewed; equality of `ingress_expiry`
// additionally ties the two envelopes to the same freshness window so a valid
// consent cannot be replayed against a call with an attacker-chosen expiry.
//
// `sender` is validated by `validate_sender` with the device-principal /
// DEFAULT_SENDER allow-list; `request_type` and `nonce` may legitimately
// differ between the two envelopes and are intentionally not compared here.
impl PartialEq<ConsentRequestT> for CanisterCallT {
    fn eq(&self, other: &ConsentRequestT) -> bool {
        self.arg_hash == other.arg_hash
            && self.ingress_expiry == other.ingress_expiry
            && self.canister_id[..self.canister_id_len as usize]
                == other.canister_id[..other.canister_id_len as usize]
            && self.method_name[..self.method_name_len as usize]
                == other.method_name[..other.method_name_len as usize]
    }
}

// This allows consent_request_t == canister_call_t to work as well
impl PartialEq<CanisterCallT> for ConsentRequestT {
    fn eq(&self, other: &CanisterCallT) -> bool {
        other == self
    }
}

// Most of the verification follows:
// https://internetcomputer.org/docs/current/references/ic-interface-spec/#certification
// and comments from ICP team during development
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
    let Ok(call_request) = CanisterCallT::from_bytes(get_call_request_memory()) else {
        return ParserError::NoData as u32;
    };

    let Ok(consent_request) = ConsentRequestT::from_bytes(get_consent_request_memory()) else {
        return ParserError::NoData as u32;
    };

    // This call the PartialEq implementation
    // for canister_call_t and consent_request_t
    // which ensures canister_id, method and args are the same in both
    if call_request != consent_request {
        return ParserError::InvalidCertificate as u32;
    }

    let data = core::slice::from_raw_parts(certificate, certificate_len as usize);
    let root_key = core::slice::from_raw_parts(root_key, BLS_PUBLIC_KEY_SIZE);

    if certificate_is_some() {
        return ParserError::InvalidCertificate as u32;
    }

    let mut cert = MaybeUninit::uninit();
    let Ok(rem) = Certificate::from_bytes_into(data, &mut cert) else {
        return ParserError::InvalidCertificate as u32;
    };

    // The call and consent parsers already require their buffers to be fully
    // consumed; hold the certificate to the same rule so trailing bytes cannot
    // ride along inside a blob that otherwise verifies.
    if !rem.is_empty() {
        return ParserError::InvalidCertificate as u32;
    }

    let cert = unsafe { cert.assume_init() };

    match cert.verify(root_key) {
        Ok(false) => return ParserError::InvalidCertificate as u32,
        Err(e) => return e as u32,
        _ => {}
    }

    // The certificate has to be about this request: the status entry must sit
    // at ["request_status", <request id>], the path the IC actually certifies
    // it under, rather than the request id appearing as a label somewhere in
    // the tree.
    let request_id = &consent_request.request_id[..];
    let Ok(LookupResult::Found(_)) = HashTree::lookup_path(
        &[REQUEST_STATUS_PATH.into(), request_id.into()],
        cert.tree(),
    ) else {
        return ParserError::InvalidCertificate as u32;
    };

    // Verify ingress_expiry against certificate timestamp
    if !cert.verify_time(call_request.ingress_expiry) {
        return ParserError::InvalidCertificate as u32;
    }

    let call_sender = &call_request.sender[..call_request.sender_len as usize];
    let consent_sender = &consent_request.sender[..consent_request.sender_len as usize];

    if !validate_sender(call_sender, consent_sender) {
        return ParserError::InvalidCertificate as u32;
    }

    // Check canister_id in request/consent is within allowed canister in the
    // certificate canister ranges
    if let Some(ranges) = cert.canister_ranges() {
        if !ranges.is_canister_in_range(
            &call_request.canister_id[..call_request.canister_id_len as usize],
        ) {
            return ParserError::InvalidCertificate as u32;
        }
    }

    // Check for the response type embedded in the certificate
    // an error response means we can not go further
    let Ok(ConsentMessageResponse::Ok(ui)) = cert.msg_response(request_id) else {
        return ParserError::InvalidCertificate as u32;
    };

    set_ui(ui);

    // Indicates certificate was valid
    set_certificate(cert);

    ParserError::Ok as u32
}

fn validate_sender(call_sender: &[u8], consent_sender: &[u8]) -> bool {
    // The consent message was generated for whoever asked for it, so the call
    // it is bound to has to come from that same principal.
    if call_sender == consent_sender {
        return true;
    }

    // Consent messages are routinely fetched anonymously, which is why an
    // anonymous consent sender does not have to match. It used to authorise
    // *any* call sender, though; requiring the call to come from this device
    // keeps that flow working while removing the part that let the consent be
    // bound to an arbitrary third party.
    let is_default_sender = consent_sender.len() == 1 && consent_sender[0] == DEFAULT_SENDER;
    if !is_default_sender && !consent_sender.is_empty() {
        return false;
    }

    let Ok(device_principal) = device_principal() else {
        return false;
    };
    let Ok(call_sender_principal) = Principal::new(call_sender) else {
        return false;
    };
    call_sender_principal == device_principal
}
