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

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug, Clone))]
pub struct FieldDisplayIterator<'b> {
    data: FieldData<'b>,
    current_state: IteratorState,
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug, Clone))]
pub struct LineDisplayIterator<'b, const L: usize> {
    data: PageData<'b>,
    current_state: IteratorState,
    config: DisplayConfig,
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug, Clone))]
struct FieldData<'b> {
    current: &'b [u8],
    // label(key) and value
    current_field: (&'b str, &'b str),
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug, Clone))]
struct PageData<'b> {
    current: &'b [u8],
    current_line: &'b str,
}

#[derive(Default)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug, Clone))]
struct IteratorState {
    item_idx: usize,
    item_count: usize,
    // Use only for the LineDisplayIterator
    current_line_in_page: usize,
    current_line_count: usize,
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug, Clone))]
struct DisplayConfig {
    screen_width: usize,
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct ScreenPage<'b, const L: usize> {
    pub(crate) segments: [&'b str; L],
    pub(crate) num_segments: usize,
}

impl<'b> FieldDisplayIterator<'b> {
    pub fn new(data: &'b [u8], item_count: u8) -> Self {
        Self {
            data: FieldData {
                current: data,
                current_field: ("", ""),
            },
            current_state: IteratorState {
                item_idx: 0,
                item_count: item_count as usize,
                ..Default::default()
            },
        }
    }

    fn process_current_item(&mut self) -> Result<(&'b str, &'b str), ParserError> {
        let (rem, label) = parse_text(self.data.current)?;
        let (rem, value) = parse_text(rem)?;

        self.data.current = rem;

        Ok((label, value))
    }

    pub fn item_count(&self) -> usize {
        self.current_state.item_count
    }
}

impl<'b, const L: usize> LineDisplayIterator<'b, L> {
    pub fn new(data: &'b [u8], screen_width: usize, item_count: u8) -> Self {
        Self {
            data: PageData {
                current: data,
                current_line: "",
            },
            current_state: IteratorState {
                item_idx: 0,
                item_count: item_count as usize,
                current_line_in_page: 0,
                current_line_count: 0,
            },
            config: DisplayConfig { screen_width },
        }
    }

    pub fn new_with_offsets(
        data: &'b [u8],
        screen_width: usize,
        item_idx: usize,
        page_info: (usize, u8),
        item_count: u8,
    ) -> Self {
        let (offset, num_lines) = page_info;
        Self {
            data: PageData {
                current: &data[offset..],
                current_line: "",
            },
            current_state: IteratorState {
                item_idx,
                item_count: item_count as usize,
                current_line_in_page: 0,
                current_line_count: num_lines as usize,
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

    pub fn item_count(&self) -> usize {
        self.current_state.item_count
    }
}

impl<'b> Iterator for FieldDisplayIterator<'b> {
    type Item = (&'b str, &'b str);

    fn next(&mut self) -> Option<Self::Item> {
        check_canary();
        heartbeat();

        // Early return if we've processed all pages
        if self.current_state.item_idx >= self.current_state.item_count {
            return None;
        }

        self.current_state.item_idx += 1;

        self.process_current_item().ok()
    }
}

impl<'b, const L: usize> Iterator for LineDisplayIterator<'b, L> {
    type Item = ScreenPage<'b, L>;

    fn next(&mut self) -> Option<Self::Item> {
        check_canary();
        heartbeat();

        // Early return if we've processed all pages
        if self.current_state.item_idx >= self.current_state.item_count {
            return None;
        }

        // Process new page header if needed
        if self.current_state.current_line_in_page == 0 {
            self.process_new_page().ok()?;
        }

        // Create ScreenPage with fixed array
        let mut screen_page = ScreenPage {
            segments: [""; L],
            num_segments: 0,
        };

        // Process lines until page is full or we hit page line count
        while screen_page.num_segments < self.current_state.current_line_count {
            match self.process_new_line() {
                Ok(()) => {
                    screen_page.segments[screen_page.num_segments] = self.data.current_line;
                    screen_page.num_segments += 1;
                    self.current_state.current_line_in_page += 1;
                }
                Err(_) => return None,
            }
        }

        // Update state for next page if needed
        if self.current_state.current_line_in_page >= self.current_state.current_line_count {
            self.current_state.item_idx += 1;
            self.current_state.current_line_in_page = 0;
        }

        // Return completed page
        Some(screen_page)
    }
}

#[cfg(test)]
use std::fmt;

#[cfg(test)]
impl<const L: usize> fmt::Display for LineDisplayIterator<'_, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "LineDisplayIterator {{")?;
        writeln!(f, "  data: {}", self.data)?;
        writeln!(f, "  current_state: {}", self.current_state)?;
        writeln!(f, "  config: {}", self.config)?;
        write!(f, "}}")
    }
}

#[cfg(test)]
impl fmt::Display for PageData<'_> {
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
        writeln!(f, "  item_idx: {}", self.item_idx)?;
        writeln!(f, "  item_count: {}", self.item_count)?;
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
