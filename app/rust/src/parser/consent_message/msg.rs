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

use nom::bytes::complete::take;

use crate::{
    candid_header::CandidHeader,
    candid_utils::parse_text,
    constants::{MAX_CHARS_PER_LINE, MAX_LINES},
    error::{ParserError, ViewError},
    utils::{decompress_leb128, handle_ui_message},
    DisplayableItem, FromBytes, FromCandidHeader,
};

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
// or:
//device_spec: [
//   {
//     LineDisplay: {
//       characters_per_line: 35,
//       lines_per_page: 3,
//     },
//   },
// ],
pub enum ConsentMessage<'a, const PAGES: usize, const LINES: usize> {
    GenericDisplayMessage(&'a str),
    // Lazy parsing, although we ensure
    // we parse every page and line, lets store
    // this as bytes
    LineDisplayMessage(&'a [u8]),
}

impl<'a, const PAGES: usize, const LINES: usize> ConsentMessage<'a, PAGES, LINES> {
    // Hashes de los campos
    const LINE_DISPLAY_MESSAGE_HASH: u32 = 1124872921;
    const GENERIC_DISPLAY_MESSAGE_HASH: u32 = 4082495484;
    const PAGES_FIELD_HASH: u32 = 3175951172; // hash del campo pages en el record
    const LINES_FIELD_HASH: u32 = 1963056639; // hash del campo lines en el record de page
                                              // We got this after printing the type table
                                              // using candid_utils::print_type_table function

    // TODO: Check that this holds true
    // the idea snprintf(buffer, "%s\n%s\n", line1, line2)
    // but in bytes plus null terminator
    fn render_buffer() -> [u8; MAX_CHARS_PER_LINE * MAX_LINES + MAX_LINES + 1] {
        // Unfortunate we can not use const generic parameters in expresion bellow
        [0u8; MAX_CHARS_PER_LINE * MAX_LINES + MAX_LINES + 1]
    }

    fn format_page_content(
        &self,
        page: &Page<'_, LINES>,
        output: &mut [u8],
    ) -> Result<u8, ViewError> {
        crate::zlog("ConsentMessage::format_page_content\x00");

        let mut output_idx = 0;
        let mut current_line = 0;
        let mut is_new_line = true;

        for line in page.lines.iter().take(page.num_lines) {
            let input = line.as_bytes();
            let mut char_idx = 0;

            while char_idx < input.len() && current_line < MAX_LINES {
                let remaining_space = MAX_CHARS_PER_LINE.min(output.len() - output_idx);
                if remaining_space == 0 {
                    break;
                }

                // Add a space if this is a new line and we're not at the start of the output
                if !is_new_line && output_idx > 0 && output_idx < output.len() - 1 {
                    output[output_idx] = b' ';
                    output_idx += 1;
                }

                let copy_len = remaining_space.min(input.len() - char_idx);
                output[output_idx..output_idx + copy_len]
                    .copy_from_slice(&input[char_idx..char_idx + copy_len]);

                char_idx += copy_len;
                output_idx += copy_len;

                // Add hyphen if word is split and we're not at the end of the line
                if char_idx < input.len()
                    && output_idx < output.len() - 1
                    && output_idx % MAX_CHARS_PER_LINE != 0
                {
                    output[output_idx] = b'-';
                    output_idx += 1;
                }

                // Move to next line if we've filled the current line
                if output_idx % MAX_CHARS_PER_LINE == 0 {
                    if current_line < MAX_LINES - 1 && output_idx < output.len() - 1 {
                        output[output_idx] = b'\n';
                        output_idx += 1;
                        current_line += 1;
                        is_new_line = true;
                    } else {
                        break;
                    }
                } else {
                    is_new_line = false;
                }
            }

            // Move to next line after processing each input line if there's space
            if current_line < MAX_LINES - 1
                && output_idx < output.len() - 1
                && char_idx >= input.len()
            {
                output[output_idx] = b'\n';
                output_idx += 1;
                current_line += 1;
                is_new_line = true;
            }
        }

        // Null-terminate the output if there's space
        if output_idx < output.len() {
            output[output_idx] = 0;
            output_idx += 1;
        }

        Ok(output_idx as u8)
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Page<'a, const L: usize> {
    lines: [&'a str; L],
    num_lines: usize,
}

impl<'a, const L: usize> Iterator for Page<'a, L> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
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

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
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

impl<'a, const PAGES: usize, const LINES: usize> FromCandidHeader<'a>
    for ConsentMessage<'a, PAGES, LINES>
{
    fn from_candid_header<const TABLE_SIZE: usize, const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<TABLE_SIZE, MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("ConsentMessage::from_table_into\x00");

        #[cfg(test)]
        {
            crate::type_table::print_type_table(&header.type_table);
            std::println!("input: {}", hex::encode(&input[..32]));
        }

        // Read variant index
        let (rem, variant_index) = decompress_leb128(input)?;

        // Get type info from table
        let type_entry = header
            .type_table
            .find_type_entry(4)
            .ok_or(ParserError::UnexpectedType)?;

        if variant_index >= type_entry.field_count as u64 {
            return Err(ParserError::UnexpectedType);
        }

        // Get field hash and verify
        let (field_hash, _) = type_entry.fields[variant_index as usize];

        match field_hash {
            hash if hash == Self::LINE_DISPLAY_MESSAGE_HASH => {
                crate::zlog("LineDisplayMessage\n");
                // Start of the content message
                // pointing to the page count
                let start = rem;
                let out = out.as_mut_ptr() as *mut LineDisplayMessageVariant;

                unsafe {
                    addr_of_mut!((*out).0).write(MessageType::LineDisplayMessage);
                }

                // Get record type entry (type 5)
                let record_entry = header
                    .type_table
                    .find_type_entry(5)
                    .ok_or(ParserError::UnexpectedType)?;

                // Verify pages field hash
                let _ = record_entry
                    .fields
                    .iter()
                    .find(|(hash, _)| *hash == Self::PAGES_FIELD_HASH)
                    .ok_or(ParserError::UnexpectedType)?;

                // Vector of pages
                let (rem, page_count) = decompress_leb128(rem)?;

                if page_count as usize > PAGES {
                    return Err(ParserError::ValueOutOfRange);
                }

                // Debug: intenta leer la primera página
                let mut raw_line = rem;
                for _page in 0..page_count {
                    let (rem, line_count) = decompress_leb128(raw_line)?;
                    if line_count as usize > LINES {
                        return Err(ParserError::ValueOutOfRange);
                    }

                    #[cfg(test)]
                    std::println!("Page: {_page} line count: {line_count}");
                    let mut current = rem;
                    for _i in 0..line_count {
                        if let Ok((new_rem, _text)) = parse_text(current) {
                            #[cfg(test)]
                            std::println!("Line {}: {:?}", _i, _text);
                            current = new_rem;
                        }
                    }
                    raw_line = current;
                }
                // Store raw bytes for lazy parsing
                let data_len = start.len() - raw_line.len();
                let (rem, data) = take(data_len)(start)?;
                unsafe {
                    addr_of_mut!((*out).1).write(data);
                }

                Ok(rem)
            }
            hash if hash == Self::GENERIC_DISPLAY_MESSAGE_HASH => {
                let out = out.as_mut_ptr() as *mut GenericDisplayMessageVariant;
                let (rem, text) = parse_text(rem)?;
                unsafe {
                    addr_of_mut!((*out).0).write(MessageType::GenericDisplayMessage);
                    addr_of_mut!((*out).1).write(text);
                }
                Ok(rem)
            }
            _ => Err(ParserError::UnexpectedType),
        }
    }

    // fn from_candid_header<const TABLE_SIZE: usize, const MAX_ARGS: usize>(
    //     input: &'a [u8],
    //     out: &mut core::mem::MaybeUninit<Self>,
    //     header: &CandidHeader<TABLE_SIZE, MAX_ARGS>,
    // ) -> Result<&'a [u8], ParserError> {
    //     crate::zlog("ConsentMessage::from_table_into\x00");
    //     #[cfg(test)]
    //     {
    //         // std::println!("const CONSENT_MSG: &str =  \"{}\";", hex::encode(input));
    //         crate::type_table::print_type_table(&header.type_table);
    //         std::println!("input: {}", hex::encode(&input[..32]));
    //     }
    //
    //     // Read variant index
    //     let (rem, variant_index) = decompress_leb128(input)?;
    //     #[cfg(test)]
    //     std::println!("rem: {}", hex::encode(&rem[..64]));
    //
    //     // Get type info from table
    //     let type_entry = header
    //         .type_table
    //         .find_type_entry(4)
    //         .ok_or(ParserError::UnexpectedType)?;
    //
    //     #[cfg(test)]
    //     std::println!("msg_entry: {:?}", type_entry);
    //
    //     if variant_index >= type_entry.field_count as u64 {
    //         return Err(ParserError::UnexpectedType);
    //     }
    //
    //     // Get field info
    //     let (field_hash, _) = type_entry.fields[variant_index as usize];
    //     #[cfg(test)]
    //     std::println!("field_hash: {}", field_hash);
    //
    //     // Read record size - this is for the variant record
    //     let (rem, _record_size) = decompress_leb128(rem)?;
    //
    //     match field_hash {
    //         hash if hash == Self::LINE_DISPLAY_MESSAGE_HASH as u32 => {
    //             crate::zlog("LineDisplayMessage\n");
    //             let start = rem;
    //             let out = out.as_mut_ptr() as *mut LineDisplayMessageVariant;
    //
    //             unsafe {
    //                 addr_of_mut!((*out).0).write(MessageType::LineDisplayMessage);
    //             }
    //
    //             // First read the record field count for pages vector
    //             let (rem, field_count) = decompress_leb128(rem)?;
    //             #[cfg(test)]
    //             std::println!("pages_record field count: {}", field_count);
    //             #[cfg(test)]
    //             std::println!("next bytes: {}", hex::encode(&rem[..16]));
    //             // if field_count != 1 {
    //             //     // Should only have 'pages' field
    //             //     return Err(ParserError::UnexpectedType);
    //             // }
    //
    //             // Read the pages vector length
    //             let (mut rem, page_count) = decompress_leb128(rem)?;
    //             // let (new_rem, lines_count) = decompress_leb128(rem)?;
    //             #[cfg(test)]
    //             std::println!("page_count?: {}", page_count);
    //
    //             while let Ok((new_rem, text)) = parse_text(rem) {
    //                 #[cfg(test)]
    //                 std::println!("Length: {}, Text: {:?}", text.len(), text);
    //                 rem = new_rem;
    //                 // Also print next byte if available
    //                 if !rem.is_empty() {
    //                     #[cfg(test)]
    //                     std::println!("Next byte: {:02x}", rem[0]);
    //                 }
    //             }
    //
    //             if page_count as usize > PAGES {
    //                 return Err(ParserError::ValueOutOfRange);
    //             }
    //
    //             // For each page
    //             for page_idx in 0..page_count as usize {
    //                 // Read the record field count for this page (should be 1 for 'lines')
    //                 let (new_rem, field_count) = decompress_leb128(rem)?;
    //                 if field_count != 1 {
    //                     return Err(ParserError::UnexpectedType);
    //                 }
    //                 rem = new_rem;
    //
    //                 // Read the lines vector length
    //                 let (new_rem, lines_count) = decompress_leb128(rem)?;
    //                 rem = new_rem;
    //
    //                 #[cfg(test)]
    //                 std::println!("Page {}: {} lines", page_idx, lines_count);
    //
    //                 if lines_count as usize > LINES {
    //                     return Err(ParserError::ValueOutOfRange);
    //                 }
    //
    //                 // Read each line
    //                 for line_idx in 0..lines_count as usize {
    //                     let (new_rem, line_text) = parse_text(rem)?;
    //                     rem = new_rem;
    //
    //                     #[cfg(test)]
    //                     std::println!("  Line {}: {:?}", line_idx, line_text);
    //                 }
    //             }
    //
    //             // Store raw bytes for lazy parsing
    //             let read = rem.as_ptr() as usize - start.as_ptr() as usize;
    //             if read > start.len() {
    //                 return Err(ParserError::UnexpectedBufferEnd);
    //             }
    //             let data = &start[0..read];
    //             unsafe {
    //                 addr_of_mut!((*out).1).write(data);
    //             }
    //             Ok(rem)
    //         }
    //         hash if hash == Self::GENERIC_DISPLAY_MESSAGE_HASH as u32 => {
    //             // GenericDisplayMessage handling...
    //             let out = out.as_mut_ptr() as *mut GenericDisplayMessageVariant;
    //             let (rem, text) = parse_text(rem)?;
    //             unsafe {
    //                 addr_of_mut!((*out).0).write(MessageType::GenericDisplayMessage);
    //                 addr_of_mut!((*out).1).write(text);
    //             }
    //             Ok(rem)
    //         }
    //         _ => Err(ParserError::UnexpectedType),
    //     }
    // }
}
// impl<'a, const PAGES: usize, const LINES: usize> FromTableInto<'a>
//     for ConsentMessage<'a, PAGES, LINES>
// {
//     fn from_table_into<const TABLE_SIZE: usize>(
//         input: &'a [u8],
//         out: &mut core::mem::MaybeUninit<Self>,
//         table: &TypeTable<TABLE_SIZE>,
//     ) -> Result<&'a [u8], ParserError> {
//         crate::zlog("ConsentMessage::from_table_into\x00");
//
//         #[cfg(test)]
//         {
//             std::println!("const CONSENT_MSG: &str =  \"{}\";", hex::encode(input));
//             crate::type_table::print_type_table(table);
//             std::println!("input: {}", hex::encode(input));
//         }
//
//         // Read variant index
//         let (rem, variant_index) = decompress_leb128(input)?;
//
//         // Get type info from table
//         let type_entry = table
//             .find_type_entry(4)
//             .ok_or(ParserError::UnexpectedType)?;
//
//         #[cfg(test)]
//         std::println!("msg_entry: {:?}", type_entry);
//
//         if variant_index >= type_entry.field_count as u64 {
//             return Err(ParserError::UnexpectedType);
//         }
//
//         // Get field info
//         let (field_hash, _) = type_entry.fields[variant_index as usize];
//         #[cfg(test)]
//         std::println!("field_hash: {}", field_hash);
//
//         // Read record size
//         let (rem, _record_size) = decompress_leb128(rem)?;
//         #[cfg(test)]
//         std::println!("record_size: {}", _record_size);
//
//         match field_hash {
//             hash if hash == Self::LINE_DISPLAY_MESSAGE_HASH as u32 => {
//                 crate::zlog("LineDisplayMessage\n");
//                 let start = rem;
//                 let out = out.as_mut_ptr() as *mut LineDisplayMessageVariant;
//                 unsafe {
//                     addr_of_mut!((*out).0).write(MessageType::LineDisplayMessage);
//                 }
//
//                 // First vector: pages
//                 let (mut rem, page_count) = decompress_leb128(rem)?;
//                 #[cfg(test)]
//                 std::println!("Total pages: {}", page_count);
//
//                 if page_count as usize > PAGES {
//                     return Err(ParserError::ValueOutOfRange);
//                 }
//
//                 // For each page
//                 for page_idx in 0..page_count as usize {
//                     // Each page is a record containing a 'lines' vector
//                     let (new_rem, record_size) = decompress_leb128(rem)?;
//                     #[cfg(test)]
//                     std::println!("record_size: {}", record_size);
//                     rem = new_rem;
//
//                     // Read the lines vector
//                     let (new_rem, lines_count) = decompress_leb128(rem)?;
//                     rem = new_rem;
//
//                     #[cfg(test)]
//                     std::println!("Page {}: {} lines", page_idx, lines_count);
//
//                     if lines_count as usize > LINES {
//                         return Err(ParserError::ValueOutOfRange);
//                     }
//
//                     // Read each line
//                     for line_idx in 0..lines_count as usize {
//                         let (new_rem, line_text) = parse_text(rem)?;
//                         rem = new_rem;
//                         #[cfg(test)]
//                         std::println!("  Line {}: {:?}", line_idx, line_text);
//                     }
//                 }
//
//                 // Store raw bytes for lazy parsing
//                 let read = rem.as_ptr() as usize - start.as_ptr() as usize;
//                 if read > start.len() {
//                     return Err(ParserError::UnexpectedBufferEnd);
//                 }
//                 let data = &start[0..read];
//                 unsafe {
//                     addr_of_mut!((*out).1).write(data);
//                 }
//                 Ok(rem)
//             }
//             hash if hash == Self::GENERIC_DISPLAY_MESSAGE_HASH as u32 => {
//                 // ... GenericDisplayMessage handling remains the same ...
//                 Ok(rem)
//             }
//             _ => Err(ParserError::UnexpectedType),
//         }
//     }
// }

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
                // get lines per page count
                let (mut rem, page_count) = decompress_leb128(rem)?;

                // we do not probably need to limit number of pages
                // if page_count as usize > PAGES {
                //     return Err(ParserError::ValueOutOfRange);
                // }

                // now iterate over each page to parse the line they contain
                // ensure data integrity at this level at parsing, so we do not
                // have to worried about in the UI part
                for _ in 0..page_count as usize {
                    let (new_rem, lines_count) = decompress_leb128(rem)?;
                    // update our slice pointer
                    rem = new_rem;

                    // if lines_count as usize > LINES {
                    //     return Err(ParserError::ValueOutOfRange);
                    // }

                    for i in 0..lines_count as usize {
                        let (new_rem, _text) = parse_text(rem)?;
                        #[cfg(test)]
                        std::println!("*text{i}: {_text}");

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
        crate::zlog("ConsentMessage::render_item\x00");
        let title_bytes = b"ConsentMsg";
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
                let current_page = pages.nth(item_n as usize).ok_or(ViewError::NoData)?;

                let mut output = Self::render_buffer();

                // Use a Rust version of the C function to format the message
                self.format_page_content(&current_page, &mut output)?;
                handle_ui_message(&output, message, page)
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
