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
//     uint8_t *state;
//     uint32_t len;
// } parser_tx_t;
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct parsed_obj_t {
    pub state: *mut u8,
    pub len: u32,
}

/// Cast a *mut u8 to a *mut Transaction
#[macro_export]
macro_rules! certificate_from_state {
    ($ptr:expr) => {
        unsafe {
            &mut (*core::ptr::addr_of_mut!((*$ptr).state)
                .cast::<core::mem::MaybeUninit<$crate::Certificate>>())
        }
    };
}
