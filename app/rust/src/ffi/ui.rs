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

use super::context::parser_context_t;
use crate::certificate_from_state;

#[no_mangle]
pub unsafe extern "C" fn rs_getNumItems(ctx: *const parser_context_t, num_items: *mut u8) -> u32 {
    if num_items.is_null() || ctx.is_null() {
        return ParserError::ContextMismatch as u32;
    }

    let tx = certificate_from_state!(ctx as *mut parser_context_t);
    let obj = tx.assume_init_mut();

    let Ok(num) = obj.num_items() else {
        return ParserError::NoData as _;
    };

    *num_items = num;

    ParserError::Ok as u32
}

#[no_mangle]
pub unsafe extern "C" fn rs_getItem(
    ctx: *const parser_context_t,
    display_idx: u8,
    out_key: *mut i8,
    key_len: u16,
    out_value: *mut i8,
    out_len: u16,
    page_idx: u8,
    page_count: *mut u8,
) -> u32 {
    *page_count = 0u8;

    let page_count = &mut *page_count;

    let key = core::slice::from_raw_parts_mut(out_key as *mut u8, key_len as usize);
    let value = core::slice::from_raw_parts_mut(out_value as *mut u8, out_len as usize);

    if ctx.is_null() {
        return ParserError::ContextMismatch as u32;
    }

    let tx = certificate_from_state!(ctx as *mut parser_context_t);
    let obj = tx.assume_init_mut();

    match obj.render_item(display_idx, key, value, page_idx) {
        Ok(page) => {
            *page_count = page;
            ParserError::Ok as _
        }
        Err(_) => ParserError::NoData as _,
    }
}
