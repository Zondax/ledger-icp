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
    call_request::{CallRequest, ConsentMsgRequest},
    error::ParserError,
    FromBytes,
};

use core::mem::MaybeUninit;
use sha2::{Digest, Sha256};

#[no_mangle]
pub unsafe extern "C" fn parser_verify_certificate(
    certificate: *const u8,
    certificate_len: u16,
    root_key: *const u8,
    call_request: *const consent_request_t,
    consent_request: *const consent_request_t,
) -> u32 {
    if call_request.is_null()
        || consent_request.is_null()
        || certificate.is_null()
        || root_key.is_null()
    {
        return ParserError::NoData as u32;
    }

    return ParserError::Ok as u32;
}
