use crate::{constants::MAX_CHARS_PER_LINE, error::ViewError};

// New helper struct to manage buffer writing
pub struct BufferWriter<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> BufferWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    pub fn write_byte(&mut self, byte: u8) -> Result<(), ViewError> {
        if self.position >= self.buffer.len() - 1 {
            return Err(ViewError::Unknown);
        }
        self.buffer[self.position] = byte;
        self.position += 1;
        Ok(())
    }

    pub fn write_line(&mut self, line: &str, add_newline: bool) -> Result<(), ViewError> {
        let mut chars_written = 0;

        // Process each character
        for c in line.chars() {
            if chars_written >= MAX_CHARS_PER_LINE {
                break;
            }

            self.write_byte(if c.is_ascii() { c as u8 } else { b' ' })?;
            chars_written += 1;
        }

        // Pad with spaces if needed
        while chars_written < MAX_CHARS_PER_LINE {
            self.write_byte(b' ')?;
            chars_written += 1;
        }

        // Add newline if not the last line
        if add_newline {
            self.write_byte(b'\n')?;
        }

        Ok(())
    }

    pub fn finalize(mut self) -> Result<u8, ViewError> {
        // Null-terminate the buffer
        self.write_byte(0)?;
        Ok(self.position as u8)
    }
}
