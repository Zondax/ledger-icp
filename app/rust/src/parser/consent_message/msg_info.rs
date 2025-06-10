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
    candid_header::CandidHeader,
    error::{ParserError, ViewError},
    type_table::FieldType,
    DisplayableItem, FromCandidHeader,
};
use core::{mem::MaybeUninit, ptr::addr_of_mut};

use super::{msg::Msg, msg_metadata::ConsentMessageMetadata};

#[repr(C)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct ConsentInfo<'a> {
    pub message: Msg<'a>,
    pub metadata: ConsentMessageMetadata<'a>,
}

impl ConsentInfo<'_> {
    pub const METADATA: u32 = 1075439471;
    pub const MESSAGE: u32 = 1763119074;
}

impl<'a> FromCandidHeader<'a> for ConsentInfo<'a> {
    fn from_candid_header<const TABLE_SIZE: usize, const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<TABLE_SIZE, MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("ConsentInfo::from_table_into\n");

        let out = out.as_mut_ptr();

        // Get the type entry for ConsentInfo (type 1)
        let type_entry = header
            .type_table
            .find_type_entry(4)
            .ok_or(ParserError::UnexpectedType)?;

        // We know METADATA has lower hash than MESSAGE, so it comes first in memory
        // No need for sorting or vectors, just check the order is correct in the type table
        let metadata_idx = type_entry.find_field_type(Self::METADATA)?;
        let message_idx = type_entry.find_field_type(Self::MESSAGE)?;

        // Verify we have both fields
        if !matches!(metadata_idx, FieldType::Compound(_))
            || !matches!(message_idx, FieldType::Compound(_))
        {
            return Err(ParserError::UnexpectedType);
        }

        // Parse in memory order (metadata first, then message)
        let metadata = unsafe { &mut *addr_of_mut!((*out).metadata).cast() };
        let mut rem = ConsentMessageMetadata::from_candid_header(input, metadata, header)?;

        let message: &mut MaybeUninit<Msg> = unsafe { &mut *addr_of_mut!((*out).message).cast() };
        rem = Msg::from_candid_header(rem, message, header)?;

        Ok(rem)
    }
}

impl DisplayableItem for ConsentInfo<'_> {
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
