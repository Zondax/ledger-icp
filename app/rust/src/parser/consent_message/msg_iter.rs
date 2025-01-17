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
        let (rem, page_count) = decompress_leb128(data).unwrap();

        Self {
            data: PageData {
                current: rem,
                current_line: "",
            },
            current_state: IteratorState {
                page_idx: 0,
                page_count: page_count as usize,
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

        // Add check for line length
        if line.len() > self.config.screen_width {
            crate::log_num("Line too large\x00", line.len() as _);
            return Err(ParserError::LineTooLong);
        }

        self.data.current = new_rem;
        self.data.current_line = line;
        Ok(())
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

        // Check if we're starting a new page
        if self.current_state.current_line_in_page == 0 {
            self.process_new_page().ok()?;
        }

        // Process lines for this page
        while segment_count < L
            && self.current_state.current_line_in_page < self.current_state.current_line_count
        {
            self.process_new_line().ok()?;

            screen_segments[segment_count] = self.data.current_line;
            segment_count += 1;
            self.current_state.current_line_in_page += 1;
        }

        // If we completed a page
        if segment_count > 0 {
            // Update state for next iteration
            if self.current_state.current_line_in_page >= self.current_state.current_line_count {
                self.current_state.page_idx += 1;
                self.current_state.current_line_in_page = 0;
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

#[cfg(test)]
use std::fmt;

#[cfg(test)]
impl<'b, const L: usize> fmt::Display for LineDisplayIterator<'b, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "LineDisplayIterator {{")?;
        writeln!(f, "  data: {}", self.data)?;
        writeln!(f, "  current_state: {}", self.current_state)?;
        writeln!(f, "  config: {}", self.config)?;
        write!(f, "}}")
    }
}

#[cfg(test)]
impl<'b> fmt::Display for PageData<'b> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PageData {{")?;
        writeln!(f, "  current: {}", hex::encode(self.current))?;
        writeln!(f, "  current_line: \"{}\"", self.current_line)?;
        write!(f, "}}")
    }
}

#[cfg(test)]
impl fmt::Display for IteratorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "IteratorState {{")?;
        writeln!(f, "  page_idx: {}", self.page_idx)?;
        writeln!(f, "  page_count: {}", self.page_count)?;
        writeln!(f, "  current_line_in_page: {}", self.current_line_in_page)?;
        writeln!(f, "  current_line_count: {}", self.current_line_count)?;
        write!(f, "}}")
    }
}

#[cfg(test)]
impl fmt::Display for DisplayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DisplayConfig {{")?;
        writeln!(f, "  screen_width: {}", self.screen_width)?;
        write!(f, "}}")
    }
}
