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
    candid_utils::parse_text,
    constants::{MAX_CHARS_PER_LINE, MAX_LINES},
    error::{ParserError, ViewError},
    utils::{decompress_leb128, handle_ui_message},
    DisplayableItem, FromBytes,
};

// We got this after printing the type table
// using candid_utils::print_type_table function
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
// (
//   record {
//     arg = blob "\44\49\44\4c\00\01\71\04\74\6f\62\69";
//     method = "greet";
//     user_preferences = record {
//       metadata = record { utc_offset_minutes = null; language = "en" };
//       device_spec = opt variant {
//         LineDisplay = record {
//           characters_per_line = 30 : nat16;
//           lines_per_page = 3 : nat16;
//         }
//       };
//     };
//   },
// )
pub enum ConsentMessage<'a, const PAGES: usize, const LINES: usize> {
    GenericDisplayMessage(&'a str),
    // Assuming max 4 pages with 5 lines each
    // also lazy parsing, although we ensure
    // we parse every page and line, lets store
    // this as bytes
    LineDisplayMessage(&'a [u8]),
}

impl<'a, const PAGES: usize, const LINES: usize> ConsentMessage<'a, PAGES, LINES> {
    // TODO: Check that this holds true
    // the idea snprintf(buffer, "%s\n%s\n", line1, line2)
    // but in bytes plus null terminator
    fn render_buffer() -> [u8; MAX_CHARS_PER_LINE * MAX_LINES + MAX_LINES + 1] {
        // Unfortunate we can not use const generic parameters in expresion bellow
        [0u8; MAX_CHARS_PER_LINE * MAX_LINES + MAX_LINES + 1]
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Page<'a, const L: usize> {
    lines: [&'a str; L],
    num_lines: usize,
}

impl<'a, const L: usize> Page<'a, L> {
    pub fn lines(&self) -> &[&str] {
        &self.lines[..self.num_lines]
    }
}

impl<'a, const L: usize> Default for Page<'a, L> {
    fn default() -> Self {
        Self {
            lines: [""; L],
            num_lines: 0,
        }
    }
}

struct LineDisplayIterator<'b, const L: usize> {
    current: &'b [u8],
    page_idx: usize,
    page_count: u64,
}

impl<'b, const L: usize> LineDisplayIterator<'b, L> {
    fn new(data: &'b [u8]) -> Self {
        // get page count
        // Safe to unwrap, when this is invoked ConsentMessage was fully parsed
        let (rem, page_count) = decompress_leb128(data).unwrap();

        Self {
            current: rem,
            page_idx: 0,
            page_count,
        }
    }
}

impl<'b, const L: usize> Iterator for LineDisplayIterator<'b, L> {
    type Item = Page<'b, L>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.page_idx >= self.page_count as usize {
            return None;
        }

        let mut lines = [""; L];

        // item_n indicates the page number we want to show
        // but we need to parse everything before reaching the
        // requested page.
        let (mut rem, line_count) = decompress_leb128(self.current).ok()?;

        // just double check
        if line_count > L as u64 {
            return None;
        }

        for l in lines.iter_mut().take(line_count as usize) {
            let (new_rem, line) = parse_text(rem).ok()?;
            // Copy page data(two lines) into our buffer
            // only if we are at the requested page, otherwise
            // just pass through the data
            *l = line;
            rem = new_rem;
        }

        self.current = rem;
        self.page_idx += 1;

        Some(Page {
            lines,
            num_lines: line_count as usize,
        })
    }
}

impl<'a, const PAGES: usize, const LINES: usize> ConsentMessage<'a, PAGES, LINES> {
    /// Creates an iterator over the pages in
    /// the message
    pub fn pages_iter(&self) -> Option<impl Iterator<Item = Page<'a, LINES>>> {
        if let ConsentMessage::LineDisplayMessage(data) = self {
            Some(LineDisplayIterator::new(data))
        } else {
            None
        }
    }
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

impl<'a, const PAGES: usize, const LINES: usize> FromBytes<'a>
    for ConsentMessage<'a, PAGES, LINES>
{
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let (rem, variant) = decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;

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
                // get page count
                let (mut rem, page_count) = decompress_leb128(rem)?;

                // we do not probably need to limit number of pages
                if page_count as usize > PAGES {
                    return Err(ParserError::ValueOutOfRange);
                }

                // now iterate over each page to parse the line they contain
                // ensure data integrity at this level at parsing, so we do not
                // have to worried about in the UI part
                for _ in 0..page_count as usize {
                    let (new_rem, lines_count) = decompress_leb128(rem)?;
                    // update our slice pointer
                    rem = new_rem;

                    if lines_count as usize > LINES {
                        return Err(ParserError::ValueOutOfRange);
                    }

                    for _ in 0..lines_count as usize {
                        let (new_rem, _) = parse_text(rem)?;
                        // update our slice pointer
                        rem = new_rem;
                    }
                }

                let read = rem.as_ptr() as usize - start.as_ptr() as usize;
                if read > start.len() {
                    return Err(ParserError::UnexpectedBufferEnd);
                }

                // Copy Line variant data, removing the other boilerplate for parsing message
                // response
                let data = &start[0..read];

                unsafe {
                    addr_of_mut!((*out).1).write(data);
                }

                Ok(rem)
            }
        }
    }
}

impl<'a, const PAGES: usize, const LINES: usize> DisplayableItem
    for ConsentMessage<'a, PAGES, LINES>
{
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        match self {
            ConsentMessage::GenericDisplayMessage(_) => Ok(1),
            ConsentMessage::LineDisplayMessage(bytes) => {
                let (_, page_count) = decompress_leb128(bytes).map_err(|_| ViewError::NoData)?;
                Ok(page_count as u8)
            }
        }
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let title_bytes = b"ConsentRequest:";
        let title_len = title_bytes.len().min(title.len() - 1);
        title[..title_len].copy_from_slice(&title_bytes[..title_len]);
        title[title_len] = 0;

        match self {
            ConsentMessage::GenericDisplayMessage(content) => {
                let msg = content.as_bytes();
                handle_ui_message(msg, message, page)
            }
            ConsentMessage::LineDisplayMessage(bytes) => {
                let mut pages: LineDisplayIterator<'_, LINES> = LineDisplayIterator::new(bytes);
                // now get to the page we are looking for
                let current_page = pages.nth(item_n as usize).ok_or(ViewError::NoData)?;

                let mut render_data = Self::render_buffer();
                let mut at = 0;

                current_page
                    .lines
                    .iter()
                    .take(current_page.num_lines)
                    .for_each(|line| {
                        render_data[at..at + line.len()].copy_from_slice(line.as_bytes());
                        at += line.len();
                        // TODO: Not sure if adding a separator would work here
                        // lets confirm with testing
                        if at < render_data.len() {
                            render_data[at] = b'\n';
                        }
                    });

                handle_ui_message(&render_data, message, page)
            }
        }
    }
}

#[cfg(test)]
mod test_consent_message {
    use super::*;

    // Data taken from the provided certificate
    const LINE_DISPLAY_MSG: &[u8] = &[
        1, 2, 30, 80, 114, 111, 100, 117, 99, 101, 32, 116, 104, 101, 32, 102, 111, 108, 108, 111,
        119, 105, 110, 103, 32, 103, 114, 101, 101, 116, 105, 110, 103, 20, 116, 101, 120, 116, 58,
        32, 34, 72, 101, 108, 108, 111, 44, 32, 116, 111, 98, 105, 33, 34,
    ];

    const NUM_PAGES: u64 = 1;
    const PAGES: [&str; 2] = ["Produce the following greeting", "text: \"Hello, tobi!\""];

    #[test]
    fn test_iterator() {
        // use a dummy number of lines(4) per page
        let mut iter: LineDisplayIterator<'_, 4> = LineDisplayIterator::new(LINE_DISPLAY_MSG);
        let page = iter.next().unwrap();
        let different = page
            .lines()
            .iter()
            .zip(PAGES.iter())
            .any(|(pl, cl)| pl != cl);

        assert!(!different);

        assert!(iter.next().is_none());
    }
}
