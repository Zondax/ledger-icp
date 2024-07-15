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
use crate::error::ParserError;

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
