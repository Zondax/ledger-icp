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

// typedef struct {
//     const uint8_t *buffer;
//     uint16_t bufferLen;
//     uint16_t offset;
//     instruction_t ins;
//     parser_tx_t tx_obj;
// } parser_context_t;
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub buffer_len: u16,
    pub offset: u16,
    pub ins: u8,
    pub tx_obj: parse_tx_t,
}

// typedef struct {
//     uint8_t *state;
//     uint32_t len;
// } parser_tx_t;
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct parse_tx_t {
    pub state: *mut u8,
    pub len: u32,
}

/// Cast a *mut u8 to a *mut Transaction
#[macro_export]
macro_rules! certificate_from_state {
    ($ptr:expr) => {
        unsafe {
            &mut (*core::ptr::addr_of_mut!((*$ptr).tx_obj.state)
                .cast::<core::mem::MaybeUninit<$crate::Certificate>>())
        }
    };
}
