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
use crate::candid_header::CandidHeader;
use crate::candid_types::IDLTypes;
use crate::candid_utils::parse_text;
use crate::error::{ParserError, ViewError};
use crate::type_table::FieldType;
use crate::utils::{decompress_leb128, handle_ui_message};
use crate::{DisplayableItem, FromBytes, FromCandidHeader};
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

impl ErrorInfo<'_> {
    pub const DESCRIPTION: u32 = 1595738364; // hash of "description"
}

impl<'a> FromCandidHeader<'a> for ErrorInfo<'a> {
    fn from_candid_header<const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        // Get the type entry for ErrorInfo (type 11 based on your table)
        let type_entry = header
            .type_table
            .find_type_entry(11)
            .ok_or(ParserError::UnexpectedType)?;

        // Verify it's a record with one field
        if type_entry.field_count != 1 {
            return Err(ParserError::UnexpectedType);
        }

        // Verify the field is description and it's a text type
        let description_field = type_entry.find_field_type(Self::DESCRIPTION)?;
        if !matches!(description_field, FieldType::Primitive(IDLTypes::Text)) {
            return Err(ParserError::UnexpectedType);
        }

        // Parse the text as before
        let (rem, description) = parse_text(input)?;
        unsafe {
            addr_of_mut!((*out.as_mut_ptr()).description).write(description);
        }
        Ok(rem)
    }
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

impl DisplayableItem for ErrorInfo<'_> {
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

impl Error<'_> {
    pub const UNSUPPORTED_CANISTER_CALL: u32 = 260448849;
    pub const CONSENT_MESSAGE_UNAVAILABLE: u32 = 752613667;
    pub const INSUFFICIENT_PAYMENT: u32 = 1019593370;
    pub const GENERIC_ERROR: u32 = 4060111587;

    // For GenericError fields
    pub const ERROR_CODE: u32 = 1595738364; // hash of "error_code"
    pub const DESCRIPTION: u32 = 3601615940; // hash of "description"
}

impl<'a> FromCandidHeader<'a> for Error<'a> {
    fn from_candid_header<const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        // Get the variant index
        let (rem, variant_index) =
            decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;

        // Get the type entry for Error (type 9 based on your table)
        let type_entry = header
            .type_table
            .find_type_entry(9)
            .ok_or(ParserError::UnexpectedType)?;

        // Find the matching variant based on the type table
        match variant_index {
            idx if idx
                == type_entry
                    .find_field_type(Self::UNSUPPORTED_CANISTER_CALL)?
                    .as_index()
                    .unwrap() as u64 =>
            {
                let mut error_info = core::mem::MaybeUninit::uninit();
                let rem = ErrorInfo::from_candid_header(rem, &mut error_info, header)?;
                let out = out.as_mut_ptr() as *mut UnsupportedCanisterCallVariant;
                unsafe {
                    addr_of_mut!((*out).0).write(ErrorType::UnsupportedCanisterCall);
                    addr_of_mut!((*out).1).write(error_info.assume_init());
                }
                Ok(rem)
            }
            idx if idx
                == type_entry
                    .find_field_type(Self::CONSENT_MESSAGE_UNAVAILABLE)?
                    .as_index()
                    .unwrap() as u64 =>
            {
                let mut error_info = core::mem::MaybeUninit::uninit();
                let rem = ErrorInfo::from_candid_header(rem, &mut error_info, header)?;
                let out = out.as_mut_ptr() as *mut ConsentMessageUnavailableVariant;
                unsafe {
                    addr_of_mut!((*out).0).write(ErrorType::ConsentMessageUnavailable);
                    addr_of_mut!((*out).1).write(error_info.assume_init());
                }
                Ok(rem)
            }
            idx if idx
                == type_entry
                    .find_field_type(Self::INSUFFICIENT_PAYMENT)?
                    .as_index()
                    .unwrap() as u64 =>
            {
                let mut error_info = core::mem::MaybeUninit::uninit();
                let rem = ErrorInfo::from_candid_header(rem, &mut error_info, header)?;
                let out = out.as_mut_ptr() as *mut InsufficientPaymentVariant;
                unsafe {
                    addr_of_mut!((*out).0).write(ErrorType::InsufficientPayment);
                    addr_of_mut!((*out).1).write(error_info.assume_init());
                }
                Ok(rem)
            }
            idx if idx
                == type_entry
                    .find_field_type(Self::GENERIC_ERROR)?
                    .as_index()
                    .unwrap() as u64 =>
            {
                // For GenericError, we need to verify the field order from the type table
                let _generic_type_entry = header
                    .type_table
                    .find_type_entry(
                        type_entry
                            .find_field_type(Self::GENERIC_ERROR)?
                            .as_index()
                            .unwrap(),
                    )
                    .ok_or(ParserError::UnexpectedType)?;

                let (rem, error_code) =
                    decompress_leb128(rem).map_err(|_| ParserError::UnexpectedError)?;
                let (rem, description) = parse_text(rem)?;

                let out = out.as_mut_ptr() as *mut GenericErrorVariant;
                unsafe {
                    addr_of_mut!((*out).0).write(ErrorType::GenericError);
                    addr_of_mut!((*out).1).write(error_code as u32);
                    addr_of_mut!((*out).2).write(description);
                }
                Ok(rem)
            }
            _ => Err(ParserError::UnexpectedType),
        }
    }
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

impl DisplayableItem for Error<'_> {
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

        match self {
            // description message could contain symbols
            Error::UnsupportedCanisterCall(e)
            | Error::ConsentMessageUnavailable(e)
            | Error::InsufficientPayment(e) => e.render_item(item_n, title, message, page),
            Error::GenericError { description, .. } => {
                let msg = description.as_bytes();
                handle_ui_message(msg, message, page)
            }
        }
    }
}
