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
    utils::decompress_leb128,
    FromBytes,
};

const LINE_DISPLAY_MESSAGE_HASH: u64 = 1124872921;
const GENERIC_DISPLAY_MESSAGE_HASH: u64 = 4082495484;

#[repr(C)]
struct GenericDisplayMessageVariant<'a>(MessageType, &'a str);

#[repr(C)]
struct LineDisplayMessageVariant<'a>(MessageType, &'a [u8]);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    GenericDisplayMessage,
    LineDisplayMessage,
}

#[derive(Debug)]
#[repr(C)]
pub enum ConsentMessage<'a> {
    GenericDisplayMessage(&'a str),
    // Assuming max 4 pages with 5 lines each
    // also lazy parsing, although we ensure
    // we parse every page and line, lets store
    // this as bytes
    LineDisplayMessage(&'a [u8]),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Page<'a> {
    lines: [&'a str; MAX_LINES],
}

impl TryFrom<u64> for MessageType {
    type Error = ParserError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            // The hash for lineDisplay is less than GenericDisplay
            // so it is assigned index 0
            0 => Ok(Self::LineDisplayMessage),
            1 => Ok(Self::GenericDisplayMessage),
            _ => Err(ParserError::UnexpectedValue),
        }
    }
}

impl<'a> FromBytes<'a> for ConsentMessage<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let (mut rem, variant) =
            decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;

        #[cfg(test)]
        std::println!("consent_msg_variant: {}", variant);

        let message_type = MessageType::try_from(variant)?;

        match message_type {
            MessageType::GenericDisplayMessage => {
                let out = out.as_mut_ptr() as *mut GenericDisplayMessageVariant;
                let (rem, message) = parse_text(rem)?;
                unsafe {
                    addr_of_mut!((*out).0).write(message_type);
                    addr_of_mut!((*out).1).write(message);
                }
                Ok(rem)
            }
            MessageType::LineDisplayMessage => {
                let start = rem;
                let out = out.as_mut_ptr() as *mut LineDisplayMessageVariant;
                unsafe {
                    addr_of_mut!((*out).0).write(message_type);
                }
                // let pages = unsafe { &mut (*out).pages };

                let (page_count, bytes_read) = print_leb128(rem)?;

                #[cfg(test)]
                std::println!("page_count: {} (bytes read: {})", page_count, bytes_read);
                rem = &rem[bytes_read..];

                if page_count as usize > MAX_PAGES {
                    return Err(ParserError::ValueOutOfRange);
                }

                for _ in 0..page_count as usize {
                    let (line_count, bytes_read) = print_leb128(rem)?;
                    #[cfg(test)]
                    std::println!("line_count: {} (bytes read: {})", line_count, bytes_read);
                    rem = &rem[bytes_read..];

                    if line_count as usize > MAX_LINES {
                        return Err(ParserError::ValueOutOfRange);
                    }

                    for _ in 0..line_count as usize {
                        let (new_rem, line) = parse_text(rem)?;
                        #[cfg(test)]
                        std::println!("line: {}", line);
                        rem = new_rem;
                    }
                }

                let read = rem.as_ptr() as usize - start.as_ptr() as usize;
                if read > start.len() {
                    return Err(ParserError::UnexpectedBufferEnd);
                }
                let data = &start[0..read];
                unsafe {
                    addr_of_mut!((*out).1).write(data);
                }
                Ok(rem)
            }
        }
    }
}

fn print_leb128(input: &[u8]) -> Result<(u64, usize), ParserError> {
    let mut result = 0;
    let mut shift = 0;
    let mut bytes_read = 0;

    for &byte in input {
        bytes_read += 1;
        let value = (byte & 0x7f) as u64;
        result |= value << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(ParserError::UnexpectedError);
        }
    }

    Ok((result, bytes_read))
}
