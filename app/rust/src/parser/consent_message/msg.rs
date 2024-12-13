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
    check_canary,
    constants::{MAX_CHARS_PER_LINE, MAX_LINES},
    error::{ParserError, ViewError},
    utils::{decompress_leb128, handle_ui_message},
    DisplayableItem, FromCandidHeader,
};

use super::buffer_writer::BufferWriter;

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
#[cfg_attr(test, derive(Debug))]
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

    // The idea snprintf(buffer, "%s\n%s\n", line1, line2)
    // but in bytes plus null terminator
    fn render_buffer() -> [u8; MAX_CHARS_PER_LINE * MAX_LINES + MAX_LINES + 1] {
        // Unfortunate we can not use const generic parameters in expresion bellow
        [0u8; MAX_CHARS_PER_LINE * MAX_LINES + MAX_LINES + 1]
    }

    fn format_page_content(
        &self,
        page: &ScreenPage<'_, LINES>,
        out: &mut [u8],
    ) -> Result<u8, ViewError> {
        let mut writer = BufferWriter::new(out);

        for (i, &line) in page.segments.iter().take(page.num_segments).enumerate() {
            // Format each line
            writer.write_line(line, i < page.num_segments - 1)?;
        }

        writer.finalize()
    }
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
struct LineDisplayIterator<'b, const L: usize> {
    data: PageData<'b>,
    current_state: IteratorState,
    config: DisplayConfig,
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
struct PageData<'b> {
    current: &'b [u8],
    current_line: &'b str,
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
struct IteratorState {
    page_idx: usize,
    page_count: usize,
    current_line_offset: usize,
    current_line_in_page: usize,
    current_line_count: usize,
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
struct DisplayConfig {
    screen_width: usize,
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
            data: PageData {
                current: rem,
                current_line: "",
            },
            current_state: IteratorState {
                page_idx: 0,
                page_count: page_count as usize,
                current_line_offset: 0,
                current_line_in_page: 0,
                current_line_count: 0,
            },
            config: DisplayConfig { screen_width },
        }
    }

    fn process_new_page(&mut self) -> Result<(), ParserError> {
        let (rem, line_count) = decompress_leb128(self.data.current)?;
        self.data.current = rem;

        if line_count as usize > L {
            return Err(ParserError::TooManyLines);
        }

        self.current_state.current_line_count = line_count.min(L as u64) as usize;
        Ok(())
    }

    fn process_new_line(&mut self) -> Result<(), ParserError> {
        let (new_rem, line) = parse_text(self.data.current)?;
        self.data.current = new_rem;
        self.data.current_line = line;
        Ok(())
    }

    fn get_line_segment(&self) -> Option<&'b str> {
        let start = self.current_state.current_line_offset * self.config.screen_width;
        if start >= self.data.current_line.len() {
            return None;
        }
        let end = (start + self.config.screen_width).min(self.data.current_line.len());
        Some(&self.data.current_line[start..end])
    }

    pub fn page_count(&self) -> usize {
        self.current_state.page_count
    }
}

impl<'b, const L: usize> Iterator for LineDisplayIterator<'b, L> {
    type Item = ScreenPage<'b, L>;

    fn next(&mut self) -> Option<Self::Item> {
        check_canary();

        // Initialize a new ScreenPage
        let mut screen_segments = [""; L];
        let mut segment_count = 0;

        // Check if we're starting a new page
        if self.current_state.current_line_offset == 0
            && self.current_state.current_line_in_page == 0
        {
            // Reset state for new page processing
            if let Err(_) = self.process_new_page() {
                return None;
            }
        }

        // Process lines for this page
        while segment_count < L
            && self.current_state.current_line_in_page < self.current_state.current_line_count
        {
            // Process new line if needed
            if self.current_state.current_line_offset == 0 {
                if let Err(_) = self.process_new_line() {
                    return None;
                }
            }

            // Get and process the current segment
            if let Some(segment) = self.get_line_segment() {
                screen_segments[segment_count] = segment;
                segment_count += 1;

                let segment_end =
                    (self.current_state.current_line_offset + 1) * self.config.screen_width;

                if segment_end >= self.data.current_line.len() {
                    // Line is complete
                    self.current_state.current_line_offset = 0;
                    self.current_state.current_line_in_page += 1;
                } else {
                    // More segments in this line
                    self.current_state.current_line_offset += 1;
                }
            } else {
                // Move to next line
                self.current_state.current_line_in_page += 1;
                self.current_state.current_line_offset = 0;
            }
        }

        // If we completed a page
        if segment_count > 0 {
            // Update state for next iteration
            if self.current_state.current_line_in_page >= self.current_state.current_line_count {
                self.current_state.page_idx += 1;
                self.current_state.current_line_in_page = 0;
                self.current_state.current_line_offset = 0;
            }

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
        if let ConsentMessage::LineDisplayMessage(data) = self {
            #[cfg(test)]
            std::println!("data: {}", hex::encode(data));
            Some(LineDisplayIterator::new(data, screen_width))
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
        check_canary();
        match self {
            ConsentMessage::GenericDisplayMessage(_) => Ok(1),
            ConsentMessage::LineDisplayMessage(_) => {
                // Get an iterator using our standard screen width
                self.pages_iter(MAX_CHARS_PER_LINE)
                    .ok_or(ViewError::NoData)
                    .map(|pages| pages.count() as u8)
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
        check_canary();
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

                let written = self.format_page_content(&current_screen, &mut output)? as usize;
                #[cfg(test)]
                {
                    let s = core::str::from_utf8(&output[..written]).unwrap();
                    std::println!("rendered page: {}", s);
                }
                if written < message.len() {
                    crate::zlog("1PAGE\x00");
                    message[..written].copy_from_slice(&output[..written]);
                    // no need for multiple pages, except the current written one
                    Ok(1)
                } else {
                    crate::zlog("using handle_ui_message\x00");
                    handle_ui_message(&output[..written], message, page)
                }
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
    const EXPECTED_PAGES: &[&[&str]] = &[
        // Page 0
        &[
            "# Authorize another address to",
            "withdraw from your account **The",
            "following address is allowed to",
        ],
        // Page 1
        &[
            "withdraw from your account:**",
            "rdmx6-jaaaa-aaaaa-aaadq-cai **Your",
            "subaccount:**",
        ],
        // Page 2
        &[
            "00000000000000000000000000000000000",
            "00000000000000000000000000000",
            "**Requested withdrawal allowance:**",
        ],
        // Page 3
        &[
            "10 ICP ⚠ The allowance will be", // Non-ASCII '⚠' replaced with ' '
            "set to 10 ICP independently of any",
            "previous allowance. Until this",
        ],
        // Page 4
        &[
            "transaction has been executed the",
            "spender can still exercise the",
            "previous allowance (if any) to it's",
        ],
        // Page 5
        &[
            "full amount. **Expiration date:**",
            "No expiration. **Approval fee:**",
            "0.0001 ICP **Transaction fees to be",
        ],
        // Page 6
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
        let iterator = LineDisplayIterator::<LINES>::new(&msg_bytes, SCREEN_WIDTH);

        // Track which page we're on
        let mut page_idx = 0;

        // Test each page
        for screen_page in iterator {
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
