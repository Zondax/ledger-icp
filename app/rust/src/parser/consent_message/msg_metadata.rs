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
    candid_utils::{parse_opt_i16, parse_text},
    error::ParserError,
    type_table::TypeTable,
    utils::decompress_leb128,
    FromBytes, FromTableInto,
};

#[repr(C)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct ConsentMessageMetadata<'a> {
    pub language: &'a str,
    // offset in minutes
    pub utc_offset: Option<i16>,
}

impl<'a> ConsentMessageMetadata<'a> {
    pub const LANGUAGE: u32 = 2047967320; // hash of "language"
    pub const UTC_OFFSET: u32 = 1502369582;
}

impl<'a> FromTableInto<'a> for ConsentMessageMetadata<'a> {
    fn from_table_into<const TABLE_SIZE: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        _table: &TypeTable<TABLE_SIZE>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("ConsentMessageMetadata::from_table_info\n");
        #[cfg(test)]
        std::println!("input: {}", hex::encode(input));

        // Read number of fields
        let (rem, _field_count) =
            decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;

        // Then parse fields in hash order
        // UTC_OFFSET (1502369582) comes first
        let (rem, utc_offset) = parse_opt_i16(rem)?;

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

impl<'a> FromBytes<'a> for ConsentMessageMetadata<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let (rem, _) = decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;

        // read first the utc_offset, its hash is < than the language hash
        let (rem, utc_offset) = parse_opt_i16(rem)?;
        let (rem, language) = parse_text(rem)?;

        if language.is_empty() || language != "en" {
            return Err(ParserError::InvalidLanguage);
        }

        let out = out.as_mut_ptr();

        unsafe {
            addr_of_mut!((*out).language).write(language);
            addr_of_mut!((*out).utc_offset).write(utc_offset);
        }
        Ok(rem)
    }
}
