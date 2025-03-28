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

use crate::{error::ParserError, DisplayableItem};

use super::resources::UI;

#[no_mangle]
pub unsafe extern "C" fn rs_getNumItems(num_items: *mut u8) -> u32 {
    if num_items.is_null() || !UI.is_some() {
        return ParserError::ContextMismatch as u32;
    }

    // Safe to unwrap due to previous check
    let ui = UI.as_ref().unwrap();

    let Ok(num) = ui.num_items() else {
        return ParserError::NoData as _;
    };

    *num_items = num;

    ParserError::Ok as u32
}

#[no_mangle]
pub unsafe extern "C" fn rs_getItem(
    display_idx: u8,
    out_key: *mut i8,
    key_len: u16,
    out_value: *mut i8,
    out_len: u16,
    page_idx: u8,
    page_count: *mut u8,
) -> u32 {
    *page_count = 0u8;

    let key = core::slice::from_raw_parts_mut(out_key as *mut u8, key_len as usize);
    let value = core::slice::from_raw_parts_mut(out_value as *mut u8, out_len as usize);

    if !UI.is_some() {
        return ParserError::ContextMismatch as _;
    }

    // Safe to unwrap due to previous check
    let ui = UI.as_ref().unwrap();

    match ui.render_item(display_idx, key, value, page_idx) {
        Ok(page) => {
            *page_count = page;
            ParserError::Ok as _
        }
        Err(_) => ParserError::NoData as _,
    }
}
