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

use crate::{
    candid_utils::parse_text, check_canary, error::ParserError, heartbeat, utils::decompress_leb128,
};

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct LineDisplayIterator<'b, const L: usize> {
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
    pub(crate) segments: [&'b str; L],
    pub(crate) num_segments: usize,
}

impl<'b, const L: usize> LineDisplayIterator<'b, L> {
    pub fn new(data: &'b [u8], screen_width: usize) -> Self {
        crate::log_num("L\x00", L as u32);
        crate::log_num("screen_width\x00", screen_width as u32);
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
        crate::zlog("process_new_page>>\x00");
        check_canary();
        heartbeat();
        let (rem, line_count) = decompress_leb128(self.data.current)?;
        crate::log_num("line_count: \x00", line_count as u32);
        crate::log_num("after decompression: \x00", rem.len() as u32);
        self.data.current = rem;

        if line_count as usize > L {
            return Err(ParserError::TooManyLines);
        }

        self.current_state.current_line_count = line_count.min(L as u64) as usize;
        Ok(())
    }

    fn process_new_line(&mut self) -> Result<(), ParserError> {
        heartbeat();
        check_canary();
        let (new_rem, line) = parse_text(self.data.current)?;
        self.data.current = new_rem;
        self.data.current_line = line;
        Ok(())
    }

    fn get_line_segment(&self) -> Option<&'b str> {
        heartbeat();
        check_canary();
        crate::zlog("get_line_segment>>\x00");

        let start = self.current_state.current_line_offset * self.config.screen_width;
        if start >= self.data.current_line.len() {
            crate::zlog("NONE>>\x00");
            return None;
        }
        let end = (start + self.config.screen_width).min(self.data.current_line.len());
        let ret = Some(&self.data.current_line[start..end]);
        crate::zlog("get_line_segment ok>>\x00");
        ret
    }

    pub fn page_count(&self) -> usize {
        self.current_state.page_count
    }
}

impl<'b, const L: usize> Iterator for LineDisplayIterator<'b, L> {
    type Item = ScreenPage<'b, L>;

    fn next(&mut self) -> Option<Self::Item> {
        check_canary();
        heartbeat();

        // Initialize a new ScreenPage
        let mut screen_segments = [""; L];
        let mut segment_count = 0;
        crate::log_num(
            "current_line_offset: \x00",
            self.current_state.current_line_offset as u32,
        );
        crate::log_num(
            "current_line_in_page: \x00",
            self.current_state.current_line_in_page as u32,
        );

        // Check if we're starting a new page
        if self.current_state.current_line_offset == 0
            && self.current_state.current_line_in_page == 0
        {
            // Reset state for new page processing
            self.process_new_page().ok()?;
        }
        crate::zlog("page_Processed>>\x00");
        heartbeat();
        check_canary();

        // Process lines for this page
        while segment_count < L
            && self.current_state.current_line_in_page < self.current_state.current_line_count
        {
            crate::log_num("segment_count: \x00", segment_count as u32);
            crate::log_num(
                "line_offset: \x00",
                self.current_state.current_line_offset as u32,
            );
            // Process new line if needed
            if self.current_state.current_line_offset == 0 {
                crate::zlog("new_line_processed>>\x00");
                self.process_new_line().ok()?;
            }

            // Get and process the current segment
            if let Some(segment) = self.get_line_segment() {
                screen_segments[segment_count] = segment;
                segment_count += 1;

                let segment_end =
                    (self.current_state.current_line_offset + 1) * self.config.screen_width;

                if segment_end >= self.data.current_line.len() {
                    crate::zlog("line_is_complete>>\x00");
                    // Line is complete
                    self.current_state.current_line_offset = 0;
                    self.current_state.current_line_in_page += 1;
                } else {
                    crate::zlog("more_segments>>\x00");
                    // More segments in this line
                    self.current_state.current_line_offset += 1;
                }
            } else {
                // Move to next line
                crate::zlog("next_line>>\x00");
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
            crate::zlog("segment_ok>>\x00");

            Some(ScreenPage {
                segments: screen_segments,
                num_segments: segment_count,
            })
        } else {
            crate::zlog("segment_none>>\x00");
            None
        }
    }
}
