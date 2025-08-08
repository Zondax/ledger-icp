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

#[no_mangle]
pub unsafe extern "C" fn rs_get_intent(out_intent: *mut i8, intent_len: u16) -> u32 {
    if out_intent.is_null() || intent_len == 0 {
        return ParserError::NoData as u32;
    }
    
    // Clear the output buffer first
    let out_slice = core::slice::from_raw_parts_mut(out_intent as *mut u8, intent_len as usize);
    out_slice[0] = 0;
    
    if !UI.is_some() {
        return ParserError::NoData as u32;
    }
    
    // Safe to unwrap due to previous check
    let ui = UI.as_ref().unwrap();
    
    // Access the intent using the public method
    if let Some(intent) = ui.message.get_intent() {
        let intent_bytes = intent.as_bytes();
        let copy_len = core::cmp::min(intent_bytes.len(), intent_len as usize - 1);
        
        out_slice[..copy_len].copy_from_slice(&intent_bytes[..copy_len]);
        out_slice[copy_len] = 0; // Null terminate
        
        return ParserError::Ok as u32;
    }
    
    ParserError::NoData as u32
}
