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
use core::mem::MaybeUninit;

use nom::bytes::complete::take;

use crate::error::ParserError;

pub mod certificate;
pub mod consent_message;
pub mod delegation;
pub mod hash_tree;
pub mod label;
pub mod pubkey;
pub mod raw_value;
pub mod signature;
pub mod subnet_id;

///This trait defines an useful interface to parse
///objects from bytes.
///this gives different objects in a transaction
///a way to define their own deserilization implementation, allowing higher level objects to generalize the
///parsing of their inner types
pub trait FromBytes<'b>: Sized {
    /// this method is avaliable for testing only, as the preferable
    /// option is to save stack by passing the memory where the object should
    /// store itself
    #[cfg(test)]
    fn from_bytes(input: &'b [u8]) -> Result<Self, crate::error::ParserError> {
        use core::mem::MaybeUninit;

        let mut out = MaybeUninit::uninit();
        Self::from_bytes_into(input, &mut out)?;
        unsafe { Ok(out.assume_init()) }
    }

    ///Main deserialization method
    ///`input` the input data that contains the serialized form in bytes of this object.
    ///`out` the memory where this object would be stored
    ///
    /// returns the remaining bytes on success
    ///
    /// `Safety` Dealing with uninitialize memory is undefine behavior
    /// even in rust, so implementors should follow the rust documentation
    /// for MaybeUninit and unsafe guidelines.
    ///
    /// It's a good idea to always put `#[inline(never)]` on top of this
    /// function's implementation
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], crate::error::ParserError>;
}

pub fn parse_text(input: &[u8]) -> Result<(&[u8], &str), nom::Err<ParserError>> {
    let (rem, len) = crate::utils::decompress_leb128(input)?;
    let (rem, bytes) = take(len as usize)(rem)?;
    let s = core::str::from_utf8(bytes).map_err(|_| nom::Err::Error(ParserError::InvalidUtf8))?;

    Ok((rem, s))
}
