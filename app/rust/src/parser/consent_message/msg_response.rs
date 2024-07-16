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

use crate::{error::ParserError, utils::decompress_leb128, FromBytes};

use super::{msg_error::Error, msg_info::ConsentInfo};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseType {
    Ok,
    Err,
}

impl TryFrom<u64> for ResponseType {
    type Error = ParserError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Err),
            _ => Err(ParserError::InvalidResponseType),
        }
    }
}

#[repr(C)]
struct OkVariant<'a>(ResponseType, ConsentInfo<'a>);

#[repr(C)]
struct ErrVariant<'a>(ResponseType, Error<'a>);

#[derive(Debug)]
#[repr(u8)]
pub enum ConsentMessageResponse<'a> {
    Ok(ConsentInfo<'a>),
    Err(Error<'a>),
}

impl<'a> FromBytes<'a> for ConsentMessageResponse<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("ConsentMessageResponse::from_bytes_into");

        // 1. Read the "DIDL" magic number
        let (rem, _) = nom::bytes::complete::tag("DIDL")(input)
            .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;

        // 2. Parse the type table
        #[cfg(test)]
        {
            super::candid_types::print_type_table(rem)?;
        }
        let rem = super::candid_types::parse_type_table(rem)?;

        // 3. Read the variant index (M part)
        let (rem, variant_index) =
            decompress_leb128(rem).map_err(|_| ParserError::UnexpectedError)?;
        #[cfg(test)]
        std::println!("Variant index: {:?}", variant_index);

        // after inspecting the type table
        // we know that ok index is 1, and 8 for error
        // 0: variant {17724: 1, 3456837: 8}
        match variant_index {
            1 => {
                // Ok variant
                let out = out.as_mut_ptr() as *mut OkVariant;
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };
                let rem = ConsentInfo::from_bytes_into(rem, data)?;
                unsafe {
                    addr_of_mut!((*out).0).write(ResponseType::Ok);
                }
                Ok(rem)
            }
            8 => {
                // Err variant
                let out = out.as_mut_ptr() as *mut ErrVariant;
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };
                let rem = Error::from_bytes_into(rem, data)?;
                unsafe {
                    addr_of_mut!((*out).0).write(ResponseType::Err);
                }
                Ok(rem)
            }
            _ => Err(ParserError::UnexpectedType),
        }
    }
}

#[cfg(test)]
mod msg_response_test {
    use super::*;

    const MSG_DATA: &[u8] = &[
        68, 73, 68, 76, 11, 107, 2, 188, 138, 1, 1, 197, 254, 210, 1, 8, 108, 2, 239, 206, 231,
        128, 4, 2, 226, 159, 220, 200, 6, 3, 108, 1, 216, 128, 198, 208, 7, 113, 107, 2, 217, 229,
        176, 152, 4, 4, 252, 223, 215, 154, 15, 113, 108, 1, 196, 214, 180, 234, 11, 5, 109, 6,
        108, 1, 255, 187, 135, 168, 7, 7, 109, 113, 107, 4, 209, 196, 152, 124, 9, 163, 242, 239,
        230, 2, 10, 154, 133, 151, 230, 3, 10, 227, 197, 129, 144, 15, 10, 108, 2, 252, 145, 244,
        248, 5, 113, 196, 152, 177, 181, 13, 125, 108, 1, 252, 145, 244, 248, 5, 113, 1, 0, 0, 2,
        101, 110, 0, 1, 2, 30, 80, 114, 111, 100, 117, 99, 101, 32, 116, 104, 101, 32, 102, 111,
        108, 108, 111, 119, 105, 110, 103, 32, 103, 114, 101, 101, 116, 105, 110, 103, 20, 116,
        101, 120, 116, 58, 32, 34, 72, 101, 108, 108, 111, 44, 32, 116, 111, 98, 105, 33, 34,
    ];

    #[test]
    fn parse_msg_response() {
        let resp = ConsentMessageResponse::from_bytes(MSG_DATA).unwrap();
        std::println!("{:?}", resp);
    }
}
