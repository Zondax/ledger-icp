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
use core::ptr::addr_of_mut;

use crate::{
    candid_header::CandidHeader,
    candid_utils::{parse_opt_i16, parse_text},
    error::ParserError,
    FromCandidHeader,
};

#[repr(C)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct ConsentMessageMetadata<'a> {
    pub language: &'a str,
    // offset in minutes
    pub utc_offset: Option<i16>,
}

impl ConsentMessageMetadata<'_> {
    pub const LANGUAGE: u32 = 2047967320; // hash of "language"
    pub const UTC_OFFSET: u32 = 1502369582;
}

impl<'a> FromCandidHeader<'a> for ConsentMessageMetadata<'a> {
    fn from_candid_header<const TABLE_SIZE: usize, const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        _header: &CandidHeader<TABLE_SIZE, MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("ConsentMessageMetadata::from_table_info\n");

        // Then parse fields in hash order
        // UTC_OFFSET (1502369582) comes first
        let (rem, utc_offset) = parse_opt_i16(input)?;

        // Then LANGUAGE (2047967320)
        let (rem, language) = parse_text(rem)?;

        if language.is_empty() || language != "en" {
            return Err(ParserError::InvalidLanguage);
        }

        // Write values to output
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).language).write(language);
            addr_of_mut!((*out).utc_offset).write(utc_offset);
        }

        Ok(rem)
    }
}
