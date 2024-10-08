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
use crate::{
    constants::{MAX_LINES, MAX_PAGES},
    error::{ParserError, ViewError},
    DisplayableItem, FromBytes,
};
use core::{mem::MaybeUninit, ptr::addr_of_mut};

use super::{msg::ConsentMessage, msg_metadata::ConsentMessageMetadata};

#[repr(C)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct ConsentInfo<'a> {
    pub message: ConsentMessage<'a, MAX_PAGES, MAX_LINES>,
    pub metadata: ConsentMessageMetadata<'a>,
}

impl<'a> FromBytes<'a> for ConsentInfo<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let out = out.as_mut_ptr();
        // Field with hash 1075439471 points to type 2 the metadata
        let metadata = unsafe { &mut *addr_of_mut!((*out).metadata).cast() };
        let rem = ConsentMessageMetadata::from_bytes_into(input, metadata)?;

        // Field with hash 1763119074 points to type 3 which is the consent messagees
        let message: &mut MaybeUninit<ConsentMessage<'_, MAX_PAGES, MAX_LINES>> =
            unsafe { &mut *addr_of_mut!((*out).message).cast() };
        let rem = ConsentMessage::from_bytes_into(rem, message)?;

        Ok(rem)
    }
}

impl<'a> DisplayableItem for ConsentInfo<'a> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        self.message.num_items()
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.message.render_item(item_n, title, message, page)
    }
}
