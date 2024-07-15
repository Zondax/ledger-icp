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
        let (rem, _) = nom::bytes::complete::tag("DIDL")(input)
            .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;

        let (rem, type_table_size) =
            decompress_leb128(rem).map_err(|_| ParserError::UnexpectedError)?;

        // Skip type table for now
        let (rem, _) = nom::bytes::complete::take(type_table_size as usize)(rem)
            .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;

        let (rem, variant) = decompress_leb128(rem).map_err(|_| ParserError::UnexpectedError)?;
        let response_type = ResponseType::try_from(variant)?;

        match response_type {
            ResponseType::Ok => {
                let out = out.as_mut_ptr() as *mut OkVariant;
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };
                let rem = ConsentInfo::from_bytes_into(rem, data)?;
                unsafe {
                    addr_of_mut!((*out).0).write(response_type);
                }
                Ok(rem)
            }
            ResponseType::Err => {
                let out = out.as_mut_ptr() as *mut ErrVariant;
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };
                let rem = Error::from_bytes_into(rem, data)?;
                unsafe {
                    addr_of_mut!((*out).0).write(response_type);
                }
                Ok(rem)
            }
        }
    }
}
