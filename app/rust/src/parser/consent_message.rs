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
pub mod msg;
pub mod msg_error;
pub mod msg_info;
pub mod msg_metadata;
pub mod msg_response;

// type icrc21_consent_info = record {
//     consent_message: icrc21_consent_message,
//     metadata: icrc21_consent_message_metadata
// };
//
// type icrc21_consent_message = variant {
//     // ... (omitting GenericDisplayMessage for brevity)
//     LineDisplayMessage: record {
//         pages: vec record {
//             // Lines of text to be displayed on a single page.
//             // Must not have more entries (lines) than specified in the icrc21_consent_message_spec.
//             // Lines must not exceed the number of characters per line specified in the icrc21_consent_message_spec.
//             lines: vec text;
//         };
//     };
// };
//
// type icrc21_consent_message_metadata = record {
//     language: text,
//     utc_offset_minutes: opt int16
// };

// Custom error type
