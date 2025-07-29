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
    constants::SHA256_DIGEST_LENGTH,
    error::{ParserError, ViewError},
};

pub trait ByteSerializable: Sized {
    fn fill_to(&self, output: &mut [u8]) -> Result<(), ParserError>;
    fn from_bytes(input: &[u8]) -> Result<&Self, ParserError>;
    fn validate(&self) -> Result<(), ParserError>;
}

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

#[inline(never)]
pub fn read_u64_le(input: &[u8]) -> Result<(&[u8], u64), ParserError> {
    if input.len() < 8 {
        return Err(ParserError::UnexpectedBufferEnd);
    }

    let value = u64::from_le_bytes([
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ]);

    Ok((&input[8..], value))
}

#[inline(never)]
pub fn read_u8(input: &[u8]) -> Result<(&[u8], u8), ParserError> {
    if input.is_empty() {
        return Err(ParserError::UnexpectedBufferEnd);
    }

    let value = u8::from_be_bytes([input[0]]);

    Ok((&input[1..], value))
}

// Format u64 as decimal string
#[inline(never)]
pub fn u64_to_str(value: u64, out: &mut [u8]) -> Result<usize, ParserError> {
    if out.is_empty() {
        return Err(ParserError::UnexpectedBufferEnd);
    }

    if value == 0 {
        if out.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd);
        }
        out[0] = b'0';
        return Ok(1);
    }

    // Convert to string by extracting digits
    let mut temp = [0u8; 20]; // max u64 has 20 digits
    let mut temp_len = 0;
    let mut n = value;

    while n > 0 {
        temp[temp_len] = (n % 10) as u8 + b'0';
        n /= 10;
        temp_len += 1;
    }

    if temp_len > out.len() {
        return Err(ParserError::UnexpectedBufferEnd);
    }

    // Write digits in correct order
    for i in 0..temp_len {
        out[i] = temp[temp_len - 1 - i];
    }

    Ok(temp_len)
}

// Format u64 with a suffix (e.g., "123 s")
#[inline(never)]
pub fn format_u64_with_suffix(
    value: u64,
    suffix: &[u8],
    out: &mut [u8],
) -> Result<usize, ParserError> {
    // First convert the number to string
    let num_len = u64_to_str(value, out)?;

    // Check if we have space for the suffix
    let suffix_len = suffix.len();
    let total_len = num_len + 1 + suffix_len; // +1 for space

    if total_len > out.len() {
        return Err(ParserError::UnexpectedBufferEnd);
    }

    // Add space
    out[num_len] = b' ';

    // Add suffix
    out[num_len + 1..num_len + 1 + suffix_len].copy_from_slice(suffix);

    Ok(total_len)
}

// Format a u64 value with decimal places and optional symbol
#[inline(never)]
pub fn format_token_amount(
    amount: u64,
    decimals: u8,
    symbol: &str,
    out: &mut [u8],
) -> Result<usize, ParserError> {
    let mut write_pos = 0;

    // Convert amount to string first
    let mut temp = [0u8; 20];
    let amount_len = u64_to_str(amount, &mut temp)?;

    // Handle decimal formatting
    if decimals == 0 || amount == 0 {
        // No decimals or zero amount, just copy the amount
        if amount_len > out.len() {
            return Err(ParserError::UnexpectedBufferEnd);
        }
        out[..amount_len].copy_from_slice(&temp[..amount_len]);
        write_pos = amount_len;
    } else {
        let decimals_usize = decimals as usize;

        if amount_len > decimals_usize {
            // We have both integer and decimal parts
            let int_part_len = amount_len - decimals_usize;

            if int_part_len + 1 + decimals_usize > out.len() {
                return Err(ParserError::UnexpectedBufferEnd);
            }

            // Copy integer part
            out[..int_part_len].copy_from_slice(&temp[..int_part_len]);
            write_pos = int_part_len;

            // Check if we need decimal part (find last non-zero digit)
            let mut last_non_zero = int_part_len; // Start from the beginning of decimal part
            for i in (int_part_len..amount_len).rev() {
                if temp[i] != b'0' {
                    last_non_zero = i + 1;
                    break;
                }
            }

            // Only add decimal part if there are non-zero digits
            if last_non_zero > int_part_len {
                // Add decimal point
                out[write_pos] = b'.';
                write_pos += 1;

                // Copy decimal part without trailing zeros
                let decimal_len = last_non_zero - int_part_len;
                out[write_pos..write_pos + decimal_len]
                    .copy_from_slice(&temp[int_part_len..last_non_zero]);
                write_pos += decimal_len;
            }
        } else {
            // Need to pad with zeros (amount is less than decimal places)
            let total_needed = 2 + decimals_usize; // "0." + decimals
            if total_needed > out.len() {
                return Err(ParserError::UnexpectedBufferEnd);
            }

            out[write_pos] = b'0';
            write_pos += 1;
            out[write_pos] = b'.';
            write_pos += 1;

            // Add leading zeros if needed
            let zeros_needed = decimals_usize - amount_len;
            for _ in 0..zeros_needed {
                out[write_pos] = b'0';
                write_pos += 1;
            }

            // Copy the amount
            out[write_pos..write_pos + amount_len].copy_from_slice(&temp[..amount_len]);
            write_pos += amount_len;

            // Remove trailing zeros
            while write_pos > 2 && out[write_pos - 1] == b'0' {
                write_pos -= 1;
            }
            // If all decimals were zeros, remove the decimal point too
            if write_pos == 2 && out[1] == b'.' {
                write_pos = 1;
            }
        }
    }

    // Add symbol if provided
    if !symbol.is_empty() {
        let symbol_bytes = symbol.as_bytes();
        let symbol_len = symbol_bytes.len();

        if write_pos + 1 + symbol_len > out.len() {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        // Add space before symbol
        out[write_pos] = b' ';
        write_pos += 1;

        // Add symbol
        out[write_pos..write_pos + symbol_len].copy_from_slice(symbol_bytes);
        write_pos += symbol_len;
    }

    Ok(write_pos)
}

// Helper function to hash data with SHA256
pub fn hash(data: &[u8]) -> [u8; SHA256_DIGEST_LENGTH] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; SHA256_DIGEST_LENGTH];
    hash.copy_from_slice(&result);
    hash
}

#[inline(never)]
pub fn hash_str(s: &str) -> [u8; SHA256_DIGEST_LENGTH] {
    hash(s.as_bytes())
}

// Function to hash binary blobs
#[inline(never)]
pub fn hash_blob(blob: &[u8]) -> [u8; SHA256_DIGEST_LENGTH] {
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
