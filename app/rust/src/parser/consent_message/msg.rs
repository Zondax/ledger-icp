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
    DisplayableItem, FromCandidHeader,
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
#[derive(Debug)]
#[repr(u8)] // Important: same representation as MessageType
pub enum ConsentMessage<'a, const PAGES: usize, const LINES: usize> {
    GenericDisplayMessage(&'a str),
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
        page: &ScreenPage<'_, LINES>,
        output: &mut [u8],
    ) -> Result<u8, ViewError> {
        crate::zlog("ConsentMessage::format_page_content\x00");
        let mut output_idx = 0;
        let mut current_line = 0;

        // Process each segment (which is already pre-formatted to screen width)
        for segment in page.segments.iter().take(page.num_segments) {
            if current_line >= MAX_LINES {
                break;
            }

            let input = segment.as_bytes();
            if input.is_empty() {
                continue;
            }

            // Copy the pre-formatted segment
            let remaining_space = MAX_CHARS_PER_LINE.min(output.len() - output_idx);
            if remaining_space == 0 {
                break;
            }

            let copy_len = remaining_space.min(input.len());
            output[output_idx..output_idx + copy_len].copy_from_slice(&input[..copy_len]);
            output_idx += copy_len;

            // Add newline if we're not at the last line
            if current_line < MAX_LINES - 1 && output_idx < output.len() - 1 {
                output[output_idx] = b'\n';
                output_idx += 1;
                current_line += 1;
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
    screen_width: usize,
    current_line_offset: usize,
    current_line_in_page: usize,
    current_line_count: usize,
    current_line: &'b str, // Store current line being processed
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct ScreenPage<'b, const L: usize> {
    segments: [&'b str; L],
    num_segments: usize,
}

impl<'b, const L: usize> LineDisplayIterator<'b, L> {
    fn new(data: &'b [u8], screen_width: usize) -> Self {
        let (rem, page_count) = decompress_leb128(data).unwrap();
        Self {
            current: rem,
            page_idx: 0,
            page_count,
            screen_width,
            current_line_offset: 0,
            current_line_in_page: 0,
            current_line_count: 0,
            current_line: "",
        }
    }

    fn get_line_segment<'a>(&self, line: &'a str) -> Option<&'a str> {
        let start = self.current_line_offset * self.screen_width;
        if start >= line.len() {
            return None;
        }
        let end = (start + self.screen_width).min(line.len());
        Some(&line[start..end])
    }
}

impl<'b, const L: usize> Iterator for LineDisplayIterator<'b, L> {
    type Item = ScreenPage<'b, L>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.page_idx >= self.page_count as usize {
            return None;
        }

        let mut screen_segments = [""; L];
        let mut segment_count = 0;

        // If we're starting a new page, read its line count
        if self.current_line_in_page == 0 {
            let (rem, line_count) = decompress_leb128(self.current).ok()?;
            self.current = rem;
            self.current_line_count = line_count as usize;
            if line_count > L as u64 {
                return None;
            }
        }

        // Process lines in the current page
        while self.current_line_in_page < self.current_line_count {
            // Parse the line text if we're at offset 0
            if self.current_line_offset == 0 {
                let (new_rem, line) = parse_text(self.current).ok()?;
                self.current = new_rem;
                self.current_line = line;
            }

            // Get the current segment of this line
            if let Some(segment) = self.get_line_segment(self.current_line) {
                screen_segments[segment_count] = segment;
                segment_count += 1;

                let line_finished =
                    (self.current_line_offset + 1) * self.screen_width >= self.current_line.len();

                if segment_count >= L || line_finished {
                    // If line is finished, move to next line
                    if line_finished {
                        self.current_line_offset = 0;
                        self.current_line_in_page += 1;
                    } else {
                        // Otherwise continue with next segment of current line
                        self.current_line_offset += 1;
                    }

                    // Return screen if full
                    if segment_count >= L {
                        // Check if we need to move to next page
                        if self.current_line_in_page >= self.current_line_count
                            && self.current_line_offset == 0
                        {
                            self.page_idx += 1;
                            self.current_line_in_page = 0;
                        }
                        return Some(ScreenPage {
                            segments: screen_segments,
                            num_segments: segment_count,
                        });
                    }
                } else {
                    // Move to next segment of current line
                    self.current_line_offset += 1;
                }
            }
        }

        // Return any remaining segments if we finished the page
        if segment_count > 0 {
            self.page_idx += 1;
            self.current_line_in_page = 0;
            self.current_line_offset = 0;
            Some(ScreenPage {
                segments: screen_segments,
                num_segments: segment_count,
            })
        } else {
            None
        }
    }
}

impl<'a, const PAGES: usize, const LINES: usize> ConsentMessage<'a, PAGES, LINES> {
    pub fn pages_iter(
        &self,
        screen_width: usize,
    ) -> Option<impl Iterator<Item = ScreenPage<'a, LINES>>> {
        crate::zlog("ConsentMessage::pages_iter\x00");
        if let ConsentMessage::LineDisplayMessage(data) = self {
            Some(LineDisplayIterator::new(data, screen_width))
        } else {
            None
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
        // Title handling remains the same
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
                // Use screen width of 35 characters
                let mut pages = LineDisplayIterator::new(bytes, 35);
                let current_page = pages.nth(item_n as usize).ok_or(ViewError::NoData)?;
                let mut output = Self::render_buffer();

                // Format the screen page content
                self.format_page_content(&current_page, &mut output)?;
                handle_ui_message(&output, message, page)
            }
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
        crate::zlog("ConsentMessage::from_candid_header\x00");

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
                // Start of the content message
                // pointing to the page count
                let start = rem;

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
                #[cfg(test)]
                std::println!("LineDisplayContent****\n {}", hex::encode(data));

                let out = out.as_mut_ptr() as *mut LineDisplayMessageVariant;
                unsafe {
                    // Write the variant tag first
                    addr_of_mut!((*out).0).write(MessageType::LineDisplayMessage);
                    // Then write the data
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
}

impl<'a, const PAGES: usize, const LINES: usize> DisplayableItem
    for ConsentMessage<'a, PAGES, LINES>
{
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        crate::zlog("ConsentMessage::num_items\x00");
        match self {
            ConsentMessage::GenericDisplayMessage(_) => Ok(1),
            ConsentMessage::LineDisplayMessage(_) => {
                // Get an iterator using our standard screen width
                if let Some(mut pages) = self.pages_iter(MAX_CHARS_PER_LINE) {
                    let mut total_screens = 0u8;
                    while pages.next().is_some() {
                        total_screens = total_screens.saturating_add(1);
                    }
                    Ok(total_screens)
                } else {
                    Err(ViewError::NoData)
                }
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
            ConsentMessage::LineDisplayMessage(_) => {
                // Use the existing pages_iter method with our standard screen width
                let mut pages = self
                    .pages_iter(MAX_CHARS_PER_LINE)
                    .ok_or(ViewError::NoData)?;
                let current_screen = pages.nth(item_n as usize).ok_or(ViewError::NoData)?;
                let mut output = Self::render_buffer();

                self.format_page_content(&current_screen, &mut output)?;
                handle_ui_message(&output, message, page)
            }
        }
    }
}

#[cfg(test)]
mod tests_msg_display {
    use super::*;
    use std::string::String;

    const SCREEN_WIDTH: usize = 35;
    const SMALL_SCREEN_WIDTH: usize = 15;
    const LINES: usize = 3; // Each page has exactly 3 lines
    const MSG_DATA: &str = "07031e2320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e74202a2a5468651f666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f031d77697468647261772066726f6d20796f7572206163636f756e743a2a2a2272646d78362d6a616161612d61616161612d61616164712d636169202a2a596f75720d7375626163636f756e743a2a2a032330303030303030303030303030303030303030303030303030303030303030303030301d3030303030303030303030303030303030303030303030303030303030232a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a032031302049435020e29aa02054686520616c6c6f77616e63652077696c6c2062652273657420746f2031302049435020696e646570656e64656e746c79206f6620616e791e70726576696f757320616c6c6f77616e63652e20556e74696c207468697303217472616e73616374696f6e20686173206265656e206578656375746564207468651e7370656e6465722063616e207374696c6c206578657263697365207468652370726576696f757320616c6c6f77616e63652028696620616e792920746f2069742773032166756c6c20616d6f756e742e202a2a45787069726174696f6e20646174653a2a2a204e6f2065787069726174696f6e2e202a2a417070726f76616c206665653a2a2a23302e3030303120494350202a2a5472616e73616374696f6e206665657320746f206265031a7061696420627920796f7572207375626163636f756e743a2a2a2330303030303030303030303030303030303030303030303030303030303030303030301d3030303030303030303030303030303030303030303030303030303030";
    // Expected content per page
    const EXPECTED_PAGES: &[&[&str]] = &[
        &[
            "# Authorize another address to",
            "withdraw from your account **The",
            "following address is allowed to",
        ],
        &[
            "withdraw from your account:**",
            "rdmx6-jaaaa-aaaaa-aaadq-cai **Your",
            "subaccount:**",
        ],
        &[
            "00000000000000000000000000000000000",
            "00000000000000000000000000000",
            "**Requested withdrawal allowance:**",
        ],
        &[
            "10 ICP ⚠ The allowance will be",
            "set to 10 ICP independently of any",
            "previous allowance. Until this",
        ],
        &[
            "transaction has been executed the",
            "spender can still exercise the",
            "previous allowance (if any) to it's",
        ],
        &[
            "full amount. **Expiration date:**",
            "No expiration. **Approval fee:**",
            "0.0001 ICP **Transaction fees to be",
        ],
        &[
            "paid by your subaccount:**",
            "00000000000000000000000000000000000",
            "00000000000000000000000000000",
        ],
    ];

    #[test]
    fn test_line_display_iterator() {
        let msg_bytes = hex::decode(MSG_DATA).unwrap();

        // Create iterator
        let mut iterator = LineDisplayIterator::<LINES>::new(&msg_bytes, SCREEN_WIDTH);

        // Track which page we're on
        let mut page_idx = 0;

        // Test each page
        while let Some(screen_page) = iterator.next() {
            assert!(page_idx < EXPECTED_PAGES.len(), "Too many pages produced");

            // Verify number of segments matches expected
            assert_eq!(
                screen_page.num_segments,
                EXPECTED_PAGES[page_idx].len(),
                "Wrong number of segments on page {}",
                page_idx
            );

            // Verify each line matches expected
            for (i, segment) in screen_page
                .segments
                .iter()
                .take(screen_page.num_segments)
                .enumerate()
            {
                assert_eq!(
                    *segment, EXPECTED_PAGES[page_idx][i],
                    "Mismatch on page {}, line {}",
                    page_idx, i
                );

                // Verify line length is within screen width
                assert!(
                    segment.len() <= SCREEN_WIDTH,
                    "Line exceeds screen width on page {}, line {}",
                    page_idx,
                    i
                );
            }

            page_idx += 1;
        }

        // Verify we got all expected pages
        assert_eq!(
            page_idx,
            EXPECTED_PAGES.len(),
            "Wrong number of pages produced"
        );
    }

    #[test]
    fn test_line_segments_within_width() {
        let msg_bytes = hex::decode(MSG_DATA).unwrap();
        let mut iterator = LineDisplayIterator::<LINES>::new(&msg_bytes, SMALL_SCREEN_WIDTH);
        let mut page_idx = 0;

        let mut current_page = 0;
        let mut current_line = 0;
        let mut accumulated = String::new();

        while let Some(screen_page) = iterator.next() {
            std::println!(
                "Page {} with {} segments:",
                page_idx,
                screen_page.num_segments
            );

            for segment in screen_page.segments.iter().take(screen_page.num_segments) {
                std::println!("  Segment: '{}' (len: {})", segment, segment.len());

                // Core requirements check
                assert!(
                    segment.len() <= SMALL_SCREEN_WIDTH,
                    "Found segment exceeding screen width: '{}' (length: {})",
                    segment,
                    segment.len()
                );

                assert!(
                    screen_page.num_segments <= LINES,
                    "Too many segments on page {}: {}",
                    page_idx,
                    screen_page.num_segments
                );

                // Optional: Verify segments reconstruct original content
                accumulated.push_str(segment);

                // If this was the last segment of a line, verify it matches original
                if accumulated.len() >= EXPECTED_PAGES[current_page][current_line].len() {
                    assert!(
                    EXPECTED_PAGES[current_page][current_line].contains(&accumulated),
                    "Reconstructed line doesn't match original.\nOriginal: '{}'\nReconstructed: '{}'",
                    EXPECTED_PAGES[current_page][current_line],
                    accumulated
                );

                    accumulated.clear();
                    current_line += 1;
                    if current_line >= EXPECTED_PAGES[current_page].len() {
                        current_page += 1;
                        current_line = 0;
                    }
                }
            }

            page_idx += 1;
        }

        // Verify all content was processed
        assert!(current_page > 0, "No pages were processed");
    }
}
