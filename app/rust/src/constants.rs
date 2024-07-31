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

pub const CBOR_TAG: u64 = 55799;
pub const CBOR_CERTIFICATE_TAG: u64 = CBOR_TAG;
pub const CALL_REQUEST_TAG: u64 = CBOR_TAG;
pub const CONSENT_MSG_REQUEST_TAG: u64 = CBOR_TAG;
pub const CANISTER_RANGES_TAG: u64 = CBOR_TAG;
