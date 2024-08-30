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
use crate::error::{ParserError, ViewError};

/// This function returns the index of the first null byte in the slice
#[cfg(test)]
pub fn strlen(s: &[u8]) -> usize {
    let mut count = 0;
    while let Some(&c) = s.get(count) {
        if c == 0 {
            return count;
        }
        count += 1;
    }

    panic!("byte slice did not terminate with null byte, s: {:x?}", s)
}

/// This function returns the index of the
/// first null byte in the slice or the total len of the slice,
/// whichever comes first
pub fn rs_strlen(s: &[u8]) -> usize {
    let mut count = 0;
    while let Some(&c) = s.get(count) {
        if c == 0 {
            return count;
        }
        count += 1;
    }

    s.len()
}

pub fn compress_leb128(mut value: u64, buf: &mut [u8]) -> &[u8] {
    let mut i = 0;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf[i] = byte;
        i += 1;
        if value == 0 {
            break;
        }
    }
    &buf[..i]
}

pub fn compress_sleb128(mut value: i64, buf: &mut [u8]) -> &[u8] {
    let mut i = 0;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0) {
            buf[i] = byte;
            i += 1;
            break;
        } else {
            byte |= 0x80;
            buf[i] = byte;
            i += 1;
        }
    }
    &buf[..i]
}

#[inline(never)]
pub fn decompress_leb128(input: &[u8]) -> Result<(&[u8], u64), ParserError> {
    let mut v = 0;
    let mut i = 0;
    let mut shift = 0;

    while i < 10 && i < input.len() {
        let b = (input[i] & 0x7f) as u64;
        if shift >= 63 && b > 1 {
            // This will overflow u64
            break;
        }
        v |= b << shift;
        if input[i] & 0x80 == 0 {
            return Ok((&input[(i + 1)..], v));
        }
        shift += 7;
        i += 1;
    }
    Err(ParserError::UnexpectedError)
}

#[inline(never)]
pub fn decompress_sleb128(input: &[u8]) -> Result<(&[u8], i64), ParserError> {
    let mut i = 0;
    let mut v = 0;
    let mut shift = 0;

    while i < 10 && i < input.len() {
        let b = (input[i] & 0x7f) as i64;
        if shift >= 63 && b > 0 {
            if b == 0x7f && input[i] & 0x80 == 0 {
                v |= 1i64 << shift;

                return Ok((&input[(i + 1)..], v));
            }
            // This will overflow i64
            break;
        }

        v |= b << shift;
        shift += 7;

        if input[i] & 0x80 == 0 {
            if input[i] & 0x40 != 0 {
                v |= -(1i64 << shift);
            }
            return Ok((&input[(i + 1)..], v));
        }
        i += 1;
    }

    // Exit because of overflowing outputSize
    Err(ParserError::UnexpectedError)
}

// Helper function to hash data with SHA256
pub fn hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[inline(never)]
pub fn hash_str(s: &str) -> [u8; 32] {
    hash(s.as_bytes())
}

// Function to hash binary blobs
#[inline(never)]
pub fn hash_blob(blob: &[u8]) -> [u8; 32] {
    hash(blob)
}

#[inline(never)]
pub fn handle_ui_message(item: &[u8], out: &mut [u8], page: u8) -> Result<u8, ViewError> {
    crate::zlog("handle_ui_message\x00");
    let m_len = out.len() - 1; //null byte terminator
    if m_len < 1 {
        return Err(ViewError::Unknown);
    }
    if m_len <= item.len() {
        let chunk = item
            .chunks(m_len) //divide in non-overlapping chunks
            .nth(page as usize) //get the nth chunk
            .ok_or(ViewError::Unknown)?;

        out[..chunk.len()].copy_from_slice(chunk);
        out[chunk.len()] = 0; //null terminate

        let n_pages = item.len() / m_len;
        Ok(1 + n_pages as u8)
    } else {
        out[..item.len()].copy_from_slice(item);
        out[item.len()] = 0; //null terminate
        Ok(1)
    }
}

#[cfg(test)]
mod test_utils {
    use std::vec;

    use super::*;

    #[test]
    fn test_compress_decompress_leb128() {
        let numbers: [u64; 5] = [0, 1, 127, 128, 255];
        let mut buf = [0u8; 10];

        for &num in &numbers {
            let compressed = compress_leb128(num, &mut buf);
            let decompressed = decompress_leb128(compressed).expect("Failed to decompress");
            assert_eq!(decompressed.1, num, "Failed for number: {}", num);
        }
    }

    #[test]
    fn test_compress_decompress_sleb128() {
        let numbers: [i64; 5] = [0, 1, -1, 127, -128];
        let mut buf = [0u8; 10];

        for &num in &numbers {
            let compressed = compress_sleb128(num, &mut buf);
            let decompressed = decompress_sleb128(compressed).expect("Failed to decompress");
            assert_eq!(decompressed.1, num, "Failed for number: {}", num);
        }
    }

    #[test]
    fn test_shortes_leb128_repr() {
        let test_cases = [
            (0u64, vec![0x00]),
            (624485u64, vec![0xE5, 0x8E, 0x26]),
            (127u64, vec![0x7F]),
            (128u64, vec![0x80, 0x01]),
            (255u64, vec![0xFF, 0x01]),
            (300u64, vec![0xAC, 0x02]),
        ];

        for (value, expected) in test_cases.iter() {
            let mut buf = [0u8; 10];
            let encoded = compress_leb128(*value, &mut buf);
            assert_eq!(encoded, &expected[..], "Failed for value: {}", value);
        }
    }
}
