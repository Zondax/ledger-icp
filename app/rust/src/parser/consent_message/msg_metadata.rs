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

use crate::{error::ParserError, parse_text, utils::decompress_sleb128, FromBytes};

#[derive(Debug)]
#[repr(C)]
pub struct ConsentMessageMetadata<'a> {
    pub language: &'a str,
    // offset in minutes
    pub utc_offset: Option<i16>,
}

impl<'a> FromBytes<'a> for ConsentMessageMetadata<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let (rem, language) = parse_text(input)?;

        let (rem, value) = decompress_sleb128(rem)?;

        let utc_offset = if value == -1 {
            None
        } else {
            Some(value as i16)
        };

        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).language).write(language);
            addr_of_mut!((*out).utc_offset).write(utc_offset);
        }
        Ok(rem)
    }
}
