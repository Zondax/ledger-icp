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
pub const MAX_CHARS_PER_LINE: usize = 25;
pub const REPLY_PATH: &str = "reply";
pub const CANISTER_RANGES_PATH: &str = "canister_ranges";

pub const CBOR_TAG: u64 = 55799;
pub const BIG_NUM_TAG: u64 = 2;
pub const CBOR_CERTIFICATE_TAG: u64 = CBOR_TAG;
pub const CALL_REQUEST_TAG: u64 = CBOR_TAG;
pub const CONSENT_MSG_REQUEST_TAG: u64 = CBOR_TAG;
pub const CANISTER_RANGES_TAG: u64 = CBOR_TAG;

pub const PRINCIPAL_MAX_LEN: usize = 29;
// Sender are principals
pub const SENDER_MAX_LEN: usize = PRINCIPAL_MAX_LEN;
pub const CANISTER_MAX_LEN: usize = 10;
pub const REQUEST_MAX_LEN: usize = 10;
pub const METHOD_MAX_LEN: usize = 20;
pub const NONCE_MAX_LEN: usize = 32;
pub const SECONDS_PER_MINUTE: u64 = 60;
pub const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
// The max offset between the certificate.time and the call message request ingress_expiry
// otherwise, call request must be considered invalid/outdated and not processed at all
pub const MAX_CERT_INGRESS_OFFSET: u64 = 12 * SECONDS_PER_MINUTE * NANOSECONDS_PER_SECOND;
// separator_len(1-bytes) + separator(13-bytes) + hash(32-bytes)
pub const BLS_MSG_SIZE: usize = 1 + 13 + 32;
// The official root key for consent message verification
// including certificate
pub const CANISTER_ROOT_KEY: &str = "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae";

pub const DEFAULT_SENDER: u8 = 0x04;
