/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
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
pub const BLS_PUBLIC_KEY_SIZE: usize = 96;
pub const BLS_SIGNATURE_SIZE: usize = 48;
pub const MAX_LINES: usize = 2;
pub const MAX_PAGES: usize = 20;
pub const MAX_CHARS_PER_LINE: usize = 32;
pub const REPLY_PATH: &str = "reply";

pub const CBOR_TAG: u64 = 55799;
pub const CBOR_CERTIFICATE_TAG: u64 = CBOR_TAG;
pub const CALL_REQUEST_TAG: u64 = CBOR_TAG;
pub const CONSENT_MSG_REQUEST_TAG: u64 = CBOR_TAG;
pub const CANISTER_RANGES_TAG: u64 = CBOR_TAG;

pub const SENDER_MAX_LEN: usize = 29;
pub const CANISTER_MAX_LEN: usize = 10;
pub const REQUEST_MAX_LEN: usize = 10;
pub const METHOD_MAX_LEN: usize = 20;
pub const NONCE_MAX_LEN: usize = 32;
// separator_len(1-bytes) + separator(13-bytes) + hash(32-bytes)
pub const BLS_MSG_SIZE: usize = 1 + 13 + 32;
