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
    constants::{MAX_LINES, MAX_PAGES},
    error::ParserError,
    parse_text,
    utils::{decompress_leb128, decompress_sleb128},
    FromBytes,
};

#[derive(Debug)]
#[repr(C)]
pub enum ConsentMessage<'a> {
    GenericDisplayMessage(&'a str),
    // Assuming max 4 pages with 5 lines each
    LineDisplayMessage([[&'a str; MAX_LINES]; MAX_PAGES]),
}

impl<'a> FromBytes<'a> for ConsentMessage<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        // let (rem, variant) = decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;
        let (rem, variant) = decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;

        match variant {
            0 => {
                let (rem, message) = parse_text(rem)?;
                unsafe {
                    addr_of_mut!(*out.as_mut_ptr())
                        .write(ConsentMessage::GenericDisplayMessage(message));
                }
                Ok(rem)
            }
            1 => {
                let (rem, vec_type) =
                    decompress_sleb128(rem).map_err(|_| ParserError::UnexpectedError)?;
                if vec_type != -19 {
                    // Vector type
                    return Err(ParserError::UnexpectedType);
                }

                let (rem, inner_vec_type) =
                    decompress_sleb128(rem).map_err(|_| ParserError::UnexpectedError)?;
                if inner_vec_type != -19 {
                    // Vector type
                    return Err(ParserError::UnexpectedType);
                }

                let (rem, text_type) =
                    decompress_sleb128(rem).map_err(|_| ParserError::UnexpectedError)?;
                if text_type != -15 {
                    // Text type
                    return Err(ParserError::UnexpectedType);
                }

                let (rem, outer_vec_len) =
                    decompress_leb128(rem).map_err(|_| ParserError::UnexpectedError)?;

                if outer_vec_len as usize > MAX_PAGES {
                    return Err(ParserError::ValueOutOfRange);
                }

                let mut pages: [[&'a str; MAX_LINES]; MAX_PAGES] = [[""; MAX_LINES]; MAX_PAGES];

                for page_idx in 0..outer_vec_len as usize {
                    let (mut rem, inner_vec_len) =
                        decompress_leb128(rem).map_err(|_| ParserError::UnexpectedError)?;

                    if inner_vec_len as usize > MAX_LINES {
                        return Err(ParserError::ValueOutOfRange);
                    }

                    for line_idx in 0..inner_vec_len as usize {
                        let (new_rem, line) = parse_text(rem)?;
                        pages[page_idx][line_idx] = line;
                        rem = new_rem;
                    }
                }

                unsafe {
                    addr_of_mut!(*out.as_mut_ptr())
                        .write(ConsentMessage::LineDisplayMessage(pages));
                }
                Ok(rem)
            }
            _ => Err(ParserError::UnexpectedValue),
        }
    }
}
