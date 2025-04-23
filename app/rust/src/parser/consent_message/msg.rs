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
use core::{cell::Cell, mem::MaybeUninit, ptr::addr_of_mut};

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

use super::{
    buffer_writer::BufferWriter,
    msg_iter::{LineDisplayIterator, ScreenPage},
};

#[repr(C)]
struct GenericDisplayMessageVariant<'a>(MessageType, &'a str);
#[repr(C)]
struct LineDisplayMessageVariant<'a, const PAGES: usize> {
    ty: MessageType,
    data: &'a [u8],
    offsets: Cell<Option<[(usize, u8); PAGES]>>,
    page_count: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    GenericDisplayMessage,
    LineDisplayMessage,
}

#[repr(C)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Msg<'a, const PAGES: usize, const LINES: usize> {
    num_items: u8,
    msg: ConsentMessage<'a, PAGES, LINES>,
}

#[repr(u8)] // Important: same representation as MessageType
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum ConsentMessage<'a, const PAGES: usize, const LINES: usize> {
    GenericDisplayMessage(&'a str),
    LineDisplayMessage {
        data: &'a [u8],
        offsets: Cell<Option<[(usize, u8); PAGES]>>,
        page_count: u8,
    },
}

impl<const PAGES: usize, const LINES: usize> ConsentMessage<'_, PAGES, LINES> {
    const LINE_DISPLAY_MESSAGE_HASH: u32 = 1124872921;
    const GENERIC_DISPLAY_MESSAGE_HASH: u32 = 4082495484;
    const PAGES_FIELD_HASH: u32 = 3175951172;
    const LINES_FIELD_HASH: u32 = 1963056639;

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

        for &line in page.segments.iter().take(page.num_segments) {
            // always add '\n' at the end of the written line
            writer.write_line(line, true)?;
        }

        // Add null terminator after joining all segments
        writer.finalize()
    }
}

impl<'a, const PAGES: usize, const LINES: usize> ConsentMessage<'a, PAGES, LINES> {
    // Returns an iterator over the pages from the first item
    pub fn pages_iter(
        &self,
        screen_width: usize,
    ) -> Option<impl Iterator<Item = ScreenPage<'a, LINES>>> {
        match self {
            ConsentMessage::LineDisplayMessage {
                data,
                offsets,
                page_count,
            } => {
                // Get or compute offsets
                let offsets = if let Some(cached) = offsets.get() {
                    cached
                } else {
                    // Compute offsets
                    let new_offsets = Self::compute_page_offsets(data, *page_count).ok()?;
                    offsets.set(Some(new_offsets));
                    new_offsets
                };

                Some(LineDisplayIterator::new_with_offsets(
                    data,
                    screen_width,
                    0,
                    offsets[0],
                    *page_count,
                ))
            }
            _ => None,
        }
    }

    // Returns for each page the data offset and the number
    // of lines
    fn compute_page_offsets(
        data: &[u8],
        page_count: u8,
    ) -> Result<[(usize, u8); PAGES], ParserError> {
        if page_count as usize > PAGES {
            return Err(ParserError::ValueOutOfRange);
        }

        let mut offsets = [(0, 0); PAGES];
        let mut current = data;

        for element in offsets.iter_mut().take(page_count as usize) {
            let offset = data.len() - current.len();
            let (rem, line_count) = decompress_leb128(current)?;
            *element = (offset, line_count as u8);

            // Skip all lines in this page
            let mut current_page = rem;
            for _ in 0..line_count {
                let (rem, _) = parse_text(current_page)?;
                current_page = rem;
            }
            current = current_page;
        }
        Ok(offsets)
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

impl<'a, const PAGES: usize, const LINES: usize> FromCandidHeader<'a> for Msg<'a, PAGES, LINES> {
    fn from_candid_header<const TABLE_SIZE: usize, const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<TABLE_SIZE, MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("Msg::from_candid_header\x00");

        let out = out.as_mut_ptr();

        let consent_msg: &mut MaybeUninit<ConsentMessage<'a, PAGES, LINES>> =
            unsafe { &mut *addr_of_mut!((*out).msg).cast() };

        let rem = ConsentMessage::from_candid_header(input, consent_msg, header)?;

        // Precompute number of items
        unsafe {
            let m = consent_msg.assume_init_ref();
            match m {
                ConsentMessage::GenericDisplayMessage(_) => {
                    // Do not accept generic messages
                    // due to the possiblility of it containing
                    // unsupported characters
                    return Err(ParserError::UnexpectedType);
                }
                ConsentMessage::LineDisplayMessage { .. } => {
                    // Current design expects page lines to fit
                    // into MAX_CHARS_PER_LINE(otherwise it errors), this means
                    // that number of items is actually the number
                    // of pages in the message
                    let num_items = m
                        .pages_iter(MAX_CHARS_PER_LINE)
                        .ok_or(ParserError::NoData)?
                        .count() as u8;
                    addr_of_mut!((*out).num_items).write(num_items);
                }
            }
        }

        Ok(rem)
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

                // Start of the content message
                // pointing to where the page data starts
                let start = rem;

                if page_count as usize > PAGES {
                    return Err(ParserError::ValueOutOfRange);
                }

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
                        if let Ok((new_rem, text)) = parse_text(current) {
                            // Check at least that all lines fit into our screen
                            // current limit is based on nano devices
                            // stax/flex support longer lines
                            if text.len() > MAX_CHARS_PER_LINE {
                                crate::log_num("Line Length Unsupported: \x00", text.len() as _);
                                return Err(ParserError::ValueOutOfRange);
                            }

                            #[cfg(test)]
                            std::println!("Line {}: {:?}", _i, text);
                            current = new_rem;
                        }
                    }
                    raw_line = current;
                }
                // Store raw bytes for lazy parsing
                // let data_len = start.len() - raw_line.len();
                let data_len = start.len() - raw_line.len();
                let (rem, data) = take(data_len)(start)?;

                let out = out.as_mut_ptr() as *mut LineDisplayMessageVariant<PAGES>;
                unsafe {
                    addr_of_mut!((*out).ty).write(MessageType::LineDisplayMessage);
                    addr_of_mut!((*out).data).write(data);
                    addr_of_mut!((*out).page_count).write(page_count as u8);
                    addr_of_mut!((*out).offsets).write(Cell::new(None));
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

impl<const PAGES: usize, const LINES: usize> DisplayableItem for Msg<'_, PAGES, LINES> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        Ok(self.num_items)
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        check_canary();
        self.msg.render_item(item_n, title, message, page)
    }
}

impl<const PAGES: usize, const LINES: usize> DisplayableItem for ConsentMessage<'_, PAGES, LINES> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        check_canary();
        match self {
            ConsentMessage::GenericDisplayMessage(_) => Ok(1),
            ConsentMessage::LineDisplayMessage { .. } => {
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
        check_canary();
        let title_bytes = b"ConsentMsg";
        let title_len = title_bytes.len().min(title.len() - 1);
        title[..title_len].copy_from_slice(&title_bytes[..title_len]);
        title[title_len] = 0;

        match self {
            ConsentMessage::GenericDisplayMessage(..) => {
                // No Data as this kind of message is not supported
                Err(ViewError::Reject)
            }
            ConsentMessage::LineDisplayMessage {
                data,
                offsets,
                page_count,
            } => {
                let offsets = if let Some(cached) = offsets.get() {
                    cached
                } else {
                    let new_offsets = Self::compute_page_offsets(data, *page_count)
                        .map_err(|_| ViewError::NoData)?;
                    offsets.set(Some(new_offsets));
                    new_offsets
                };

                let page_info = *offsets.get(item_n as usize).ok_or(ViewError::NoData)?;

                let screen_page = LineDisplayIterator::new_with_offsets(
                    data,
                    MAX_CHARS_PER_LINE,
                    item_n as usize,
                    page_info,
                    *page_count,
                )
                .next()
                .ok_or(ViewError::NoData)?;

                let mut buff = Self::render_buffer();

                self.format_page_content(&screen_page, &mut buff)?;

                handle_ui_message(&buff, message, page)
            }
        }
    }
}

#[cfg(test)]
mod tests_msg_display {
    use super::*;

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

        let (rem, page_count) = decompress_leb128(&msg_bytes).unwrap();

        // Create iterator
        let iterator = LineDisplayIterator::<LINES>::new(rem, SCREEN_WIDTH, page_count as _);

        // Track which page we're on
        let mut page_idx = 0;

        // Test each page
        for screen_page in iterator.clone() {
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
    fn test_line_display_iterator_with_index() {
        let msg_bytes = hex::decode(MSG_DATA).unwrap();

        let (rem, page_count) = decompress_leb128(&msg_bytes).unwrap();

        let page_idx = 3;
        let offsets: [(usize, u8); 7] =
            ConsentMessage::<7, 3>::compute_page_offsets(rem, page_count as _).unwrap();

        std::println!("offsets: {:?}", offsets);

        // Create iterator
        let mut iterator = LineDisplayIterator::<LINES>::new_with_offsets(
            rem,
            SCREEN_WIDTH,
            3,
            offsets[page_idx],
            page_count as _,
        );

        let screen_page = iterator.next().unwrap();

        // Test each page

        // Verify each line matches expected
        for (i, segment) in screen_page
            .segments
            .iter()
            .take(screen_page.num_segments)
            .enumerate()
        {
            std::println!("segment {segment}");
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
    }

    #[test]
    fn test_line_segments_within_width() {
        let msg_bytes = hex::decode(MSG_DATA).unwrap();

        let (rem, page_count) = decompress_leb128(&msg_bytes).unwrap();

        // Create iterator
        let mut iterator =
            LineDisplayIterator::<LINES>::new(rem, SMALL_SCREEN_WIDTH, page_count as _);

        assert!(iterator.next().is_none());
    }
}
