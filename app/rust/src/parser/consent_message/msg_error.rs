use crate::candid_utils::parse_text;
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
use crate::utils::{decompress_leb128, handle_ui_message};
use crate::{DisplayableItem, FromBytes};
use core::ptr::addr_of_mut;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorType {
    UnsupportedCanisterCall,
    ConsentMessageUnavailable,
    InsufficientPayment,
    GenericError,
}

impl TryFrom<u64> for ErrorType {
    type Error = ParserError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UnsupportedCanisterCall),
            1 => Ok(Self::ConsentMessageUnavailable),
            2 => Ok(Self::InsufficientPayment),
            3 => Ok(Self::GenericError),
            _ => Err(ParserError::InvalidErrorResponse),
        }
    }
}

#[repr(C)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct ErrorInfo<'a> {
    pub description: &'a str,
}

impl<'a> FromBytes<'a> for ErrorInfo<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let (rem, description) = parse_text(input)?;
        unsafe {
            addr_of_mut!((*out.as_mut_ptr()).description).write(description);
        }
        Ok(rem)
    }
}

impl<'a> DisplayableItem for ErrorInfo<'a> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        Ok(1)
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let title_bytes = b"Error:";
        let title_len = title_bytes.len().min(title.len() - 1);
        title[..title_len].copy_from_slice(&title_bytes[..title_len]);
        title[title_len] = 0;
        if item_n != 0 {
            return Err(ViewError::NoData);
        }

        let msg = self.description.as_bytes();
        handle_ui_message(msg, message, page)
    }
}

#[repr(C)]
struct UnsupportedCanisterCallVariant<'a>(ErrorType, ErrorInfo<'a>);

#[repr(C)]
struct ConsentMessageUnavailableVariant<'a>(ErrorType, ErrorInfo<'a>);

#[repr(C)]
struct InsufficientPaymentVariant<'a>(ErrorType, ErrorInfo<'a>);

#[repr(C)]
struct GenericErrorVariant<'a>(ErrorType, u32, &'a str);

#[repr(u8)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum Error<'a> {
    UnsupportedCanisterCall(ErrorInfo<'a>),
    ConsentMessageUnavailable(ErrorInfo<'a>),
    InsufficientPayment(ErrorInfo<'a>),
    GenericError {
        error_code: u32,
        description: &'a str,
    },
}

impl<'a> FromBytes<'a> for Error<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let (rem, variant) = decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;
        let error_type = ErrorType::try_from(variant)?;

        match error_type {
            ErrorType::UnsupportedCanisterCall
            | ErrorType::ConsentMessageUnavailable
            | ErrorType::InsufficientPayment => {
                let mut error_info = core::mem::MaybeUninit::uninit();
                let rem = ErrorInfo::from_bytes_into(rem, &mut error_info)?;
                let out = out.as_mut_ptr();
                unsafe {
                    match error_type {
                        ErrorType::UnsupportedCanisterCall => {
                            let out = out as *mut UnsupportedCanisterCallVariant;
                            addr_of_mut!((*out).0).write(error_type);
                            addr_of_mut!((*out).1).write(error_info.assume_init());
                        }
                        ErrorType::ConsentMessageUnavailable => {
                            let out = out as *mut ConsentMessageUnavailableVariant;
                            addr_of_mut!((*out).0).write(error_type);
                            addr_of_mut!((*out).1).write(error_info.assume_init());
                        }
                        ErrorType::InsufficientPayment => {
                            let out = out as *mut InsufficientPaymentVariant;
                            addr_of_mut!((*out).0).write(error_type);
                            addr_of_mut!((*out).1).write(error_info.assume_init());
                        }
                        _ => unreachable!(),
                    }
                }
                Ok(rem)
            }
            ErrorType::GenericError => {
                let (rem, error_code) =
                    decompress_leb128(rem).map_err(|_| ParserError::UnexpectedError)?;
                let (rem, description) = parse_text(rem)?;
                let out = out.as_mut_ptr() as *mut GenericErrorVariant;
                unsafe {
                    addr_of_mut!((*out).0).write(error_type);
                    addr_of_mut!((*out).1).write(error_code as u32);
                    addr_of_mut!((*out).2).write(description);
                }
                Ok(rem)
            }
        }
    }
}

impl<'a> DisplayableItem for Error<'a> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        match self {
            Error::UnsupportedCanisterCall(e)
            | Error::ConsentMessageUnavailable(e)
            | Error::InsufficientPayment(e) => e.num_items(),
            // TODO: Check if it is worth to display error code
            Error::GenericError { .. } => Ok(1),
        }
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let title_bytes = b"Error:";
        let title_len = title_bytes.len().min(title.len() - 1);
        title[..title_len].copy_from_slice(&title_bytes[..title_len]);
        title[title_len] = 0;

        match self {
            // TODO: maybe we just show the variant name as the error message?
            // description message could contain symbols
            Error::UnsupportedCanisterCall(e)
            | Error::ConsentMessageUnavailable(e)
            | Error::InsufficientPayment(e) => e.render_item(item_n, title, message, page),
            // TODO: Check if it is worth to display error code
            Error::GenericError { description, .. } => {
                let msg = description.as_bytes();
                handle_ui_message(msg, message, page)
            }
        }
    }
}
