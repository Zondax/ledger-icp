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
use core::{mem::MaybeUninit, ptr::addr_of_mut};

use nom::bytes::complete::take;

use crate::{
    candid_header::CandidHeader,
    candid_utils::parse_text,
    check_canary,
    constants::{CANDID_HEADER_ENTRY_TYPE, DISPLAY_RECORD_TYPE},
    error::{ParserError, ViewError},
    utils::{decompress_leb128, handle_ui_message, read_u64_le, read_u8},
    DisplayableItem, FromCandidHeader,
};

// Constants for field hashes
const GENERIC_DISPLAY_MESSAGE_HASH: u32 = 4082495484;
const FIELDS_DISPLAY_HASH: u32 = 124612638;
const FIELDS_HASH: u32 = 2156826233;
const INTENT_HASH: u32 = 2659612252;

// Field value type variant hashes
const TEXT_HASH: u32 = 936573133;
const TIMESTAMP_SECONDS_HASH: u32 = 4208601451;
const DURATION_SECONDS_HASH: u32 = 2826488937;
const TOKEN_AMOUNT_HASH: u32 = 1289986449;

// Struct for fields display with intent
#[repr(C)]
struct FieldsDisplayMessageVariant<'a> {
    ty: MessageType,
    fields: &'a [u8],
    field_count: u8,
    intent: &'a str, // Add intent field
}

#[repr(C)]
struct GenericDisplayMessageVariant<'a>(MessageType, &'a str);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    FieldsDisplayMessage,
    GenericDisplayMessage,
}

#[repr(C)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Msg<'a> {
    num_items: u8,
    msg: ConsentMessage<'a>,
}

#[repr(u8)] // Important: same representation as MessageType
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum ConsentMessage<'a> {
    FieldsDisplayMessage {
        fields: &'a [u8],
        field_count: u8,
        intent: &'a str,
    },
    GenericDisplayMessage(&'a str),
}

impl<'a> ConsentMessage<'a> {}

impl TryFrom<u64> for MessageType {
    type Error = ParserError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            // The hash for FieldsDisplayMessage is less than GenericDisplay
            // so it is assigned index 0
            0 => Ok(Self::FieldsDisplayMessage),
            1 => Ok(Self::GenericDisplayMessage),
            _ => Err(ParserError::UnexpectedValue),
        }
    }
}

impl<'a> FromCandidHeader<'a> for Msg<'a> {
    fn from_candid_header<const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("Msg::from_candid_header\x00");

        let out = out.as_mut_ptr();

        let consent_msg: &mut MaybeUninit<ConsentMessage<'a>> =
            unsafe { &mut *addr_of_mut!((*out).msg).cast() };

        let rem = ConsentMessage::from_candid_header(input, consent_msg, header)?;

        // Precompute number of items
        unsafe {
            let m = consent_msg.assume_init_ref();
            match m {
                ConsentMessage::FieldsDisplayMessage { field_count, .. } => {
                    // Add 1 to field_count to include intent as item 0
                    addr_of_mut!((*out).num_items).write(*field_count + 1);
                }
                ConsentMessage::GenericDisplayMessage(_) => {
                    // Do not accept generic messages
                    // due to the possiblility of it containing
                    // unsupported characters
                    return Err(ParserError::UnexpectedType);
                }
            }
        }
        Ok(rem)
    }
}

// Helper function to skip a field value based on its type
fn skip_field_value<'a, const MAX_ARGS: usize>(
    input: &'a [u8],
    field_type_idx: usize,
    header: &CandidHeader<MAX_ARGS>,
) -> Result<&'a [u8], ParserError> {
    // Get the type entry for the field value
    let type_entry = header
        .type_table
        .find_type_entry(field_type_idx)
        .ok_or(ParserError::UnexpectedType)?;

    match type_entry.type_code {
        crate::candid_types::IDLTypes::Variant => {
            // Read variant index
            let (rem, variant_idx) = decompress_leb128(input)?;

            // Get the variant field info
            if variant_idx >= type_entry.field_count as u64 {
                return Err(ParserError::UnexpectedType);
            }

            // Additional safety check for our reduced array size
            if variant_idx >= crate::constants::MAX_FIELDS_PER_TYPE as u64 {
                return Err(ParserError::UnexpectedType);
            }

            let (variant_hash, _) = type_entry.fields[variant_idx as usize];

            // Skip based on variant type
            match variant_hash {
                TEXT_HASH => {
                    // Skip the Text record which contains a text field
                    let (rem, _) = parse_text(rem)?;
                    Ok(rem)
                }
                TIMESTAMP_SECONDS_HASH | DURATION_SECONDS_HASH => {
                    // Skip the record containing a nat64 field (amount)
                    if rem.len() < 8 {
                        return Err(ParserError::UnexpectedBufferEnd);
                    }
                    let (rem, _) = read_u64_le(rem)?;
                    Ok(rem)
                }
                TOKEN_AMOUNT_HASH => {
                    // Skip TokenAmount record (amount: u64, decimals: u8, symbol: text)
                    let (rem, _) = read_u64_le(rem)?; // amount
                    let (rem, _) = read_u8(rem)?; // decimals
                    let (rem, _) = parse_text(rem)?; // symbol
                    Ok(rem)
                }
                _ => Err(ParserError::UnexpectedType),
            }
        }
        crate::candid_types::IDLTypes::Text => {
            // If it's directly a text type (old format)
            let (rem, _) = parse_text(input)?;
            Ok(rem)
        }
        _ => Err(ParserError::UnexpectedType),
    }
}

impl<'a> FromCandidHeader<'a> for ConsentMessage<'a> {
    fn from_candid_header<const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("ConsentMessage::from_candid_header\x00");

        // Read variant index
        let (rem, variant_index) = decompress_leb128(input)?;

        // Get type info from table
        let type_entry = header
            .type_table
            .find_type_entry(CANDID_HEADER_ENTRY_TYPE)
            .ok_or(ParserError::UnexpectedType)?;

        if variant_index >= type_entry.field_count as u64 {
            return Err(ParserError::UnexpectedType);
        }

        // Additional safety check for our reduced array size
        if variant_index >= crate::constants::MAX_FIELDS_PER_TYPE as u64 {
            return Err(ParserError::UnexpectedType);
        }

        // Get field hash and verify
        let (field_hash, _) = type_entry.fields[variant_index as usize];

        match field_hash {
            hash if hash == FIELDS_DISPLAY_HASH => {
                let out = out.as_mut_ptr() as *mut FieldsDisplayMessageVariant;

                // Get record type entry for the fields display record
                let record_entry = header
                    .type_table
                    .find_type_entry(DISPLAY_RECORD_TYPE)
                    .ok_or(ParserError::UnexpectedType)?;

                // Parse fields vector first (FIELDS_HASH = 2156826233)
                let _ = record_entry
                    .fields
                    .iter()
                    .find(|(hash, _)| *hash == FIELDS_HASH)
                    .ok_or(ParserError::UnexpectedType)?;

                // Get the vector length (number of records)
                let (rem, field_count) = decompress_leb128(rem)?;

                // Store the start position of fields data
                let fields_start = rem;

                // Find the fields type in the record (type 5)
                let fields_field = record_entry
                    .fields
                    .iter()
                    .find(|(hash, _)| *hash == FIELDS_HASH)
                    .ok_or(ParserError::UnexpectedType)?;

                // Get the vector type index
                let vec_type_idx = match fields_field.1 {
                    crate::type_table::FieldType::Compound(idx) => idx,
                    _ => return Err(ParserError::UnexpectedType),
                };

                // Get the vector element type
                let vec_type_entry = header
                    .type_table
                    .find_type_entry(vec_type_idx)
                    .ok_or(ParserError::UnexpectedType)?;

                // Get the record type index from the vector
                let record_type_idx = match vec_type_entry.fields[0].1 {
                    crate::type_table::FieldType::Compound(idx) => idx,
                    _ => return Err(ParserError::UnexpectedType),
                };

                // Get the record type entry
                let field_record_entry = header
                    .type_table
                    .find_type_entry(record_type_idx)
                    .ok_or(ParserError::UnexpectedType)?;

                // Get the value type index from the record (field 1)
                let value_type_idx = match field_record_entry.fields[1].1 {
                    crate::type_table::FieldType::Compound(idx) => idx,
                    _ => return Err(ParserError::UnexpectedType),
                };

                // Calculate size of each record and total size
                let mut current = rem;
                for _ in 0..field_count {
                    // Skip key (field 0 is text)
                    let (new_rem, _) = parse_text(current)?;
                    // Skip value using the type table
                    let new_rem = skip_field_value(new_rem, value_type_idx, header)?;
                    current = new_rem;
                }

                // Calculate total size from start to end
                let total_size = fields_start.len() - current.len();

                // Take only the fields content from the correct position
                let (_rem, fields) = take(total_size)(fields_start)?;

                // Continue parsing from where we left off
                let rem = current;

                // Parse intent (INTENT_HASH = 2659612252)
                let _ = record_entry
                    .fields
                    .iter()
                    .find(|(hash, _)| *hash == INTENT_HASH)
                    .ok_or(ParserError::UnexpectedType)?;
                let (rem, intent) = parse_text(rem)?;

                unsafe {
                    addr_of_mut!((*out).ty).write(MessageType::FieldsDisplayMessage);
                    addr_of_mut!((*out).fields).write(fields);
                    addr_of_mut!((*out).field_count).write(field_count as u8);
                    addr_of_mut!((*out).intent).write(intent);
                }
                Ok(rem)
            }
            hash if hash == GENERIC_DISPLAY_MESSAGE_HASH => {
                let out = out.as_mut_ptr() as *mut GenericDisplayMessageVariant;
                let (rem, text) = parse_text(rem)?;
                unsafe {
                    addr_of_mut!((*out).0).write(MessageType::GenericDisplayMessage);
                    addr_of_mut!((*out).1).write(text);
                }
                Ok(rem)
            }
            _ => Err(ParserError::UnexpectedType),
        }
    }
}

impl DisplayableItem for Msg<'_> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        Ok(self.num_items)
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        check_canary();
        self.msg.render_item(item_n, title, message, page)
    }
}

impl DisplayableItem for ConsentMessage<'_> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        check_canary();
        match self {
            ConsentMessage::FieldsDisplayMessage { field_count, .. } => Ok(*field_count + 1), // +1 for intent
            ConsentMessage::GenericDisplayMessage(_) => Ok(1),
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
        check_canary();

        match self {
            ConsentMessage::FieldsDisplayMessage {
                fields,
                field_count,
                intent,
            } => {
                // Item 0 is the intent
                if item_n == 0 {
                    let title_text = b"Transaction Type";
                    let title_len = title_text.len().min(title.len() - 1);
                    title[..title_len].copy_from_slice(&title_text[..title_len]);
                    title[title_len] = 0;

                    // Set message to the intent text
                    return handle_ui_message(intent.as_bytes(), message, page);
                }

                // Adjust item_n for field access (subtract 1 since intent is item 0)
                let field_index = item_n - 1;

                if field_index >= *field_count {
                    return Err(ViewError::NoData);
                }

                let mut current = *fields;

                // Skip to the desired field
                for _ in 0..field_index {
                    // Skip key
                    let (rem, _) = parse_text(current).map_err(|_| ViewError::NoData)?;
                    // Skip value - need to properly skip the variant
                    let (rem, variant_idx) =
                        decompress_leb128(rem).map_err(|_| ViewError::NoData)?;
                    let rem = match variant_idx {
                        0 => {
                            // Text variant
                            let (rem, _) = parse_text(rem).map_err(|_| ViewError::NoData)?;
                            rem
                        }
                        1 => {
                            // TokenAmount - record { decimals: u8, amount: u64, symbol: text }
                            let (rem, _) = read_u8(rem).map_err(|_| ViewError::NoData)?;
                            let (rem, _) = read_u64_le(rem).map_err(|_| ViewError::NoData)?;
                            let (rem, _) = parse_text(rem).map_err(|_| ViewError::NoData)?;
                            rem
                        }
                        2 => {
                            // TimestampSeconds
                            if rem.len() < 8 {
                                return Err(ViewError::NoData);
                            }
                            let (rem, _) = read_u64_le(rem).map_err(|_| ViewError::NoData)?;
                            rem
                        }
                        3 => {
                            // DurationSeconds
                            if rem.len() < 8 {
                                return Err(ViewError::NoData);
                            }
                            let (rem, _) = read_u64_le(rem).map_err(|_| ViewError::NoData)?;
                            rem
                        }
                        _ => return Err(ViewError::NoData),
                    };
                    current = rem;
                }

                // Parse the target field
                let (rem, key) = parse_text(current).map_err(|_| ViewError::NoData)?;

                // Set the title to the key
                let key_bytes = key.as_bytes();
                let key_len = key_bytes.len().min(title.len() - 1);
                title[..key_len].copy_from_slice(&key_bytes[..key_len]);
                title[key_len] = 0;

                // Parse and render the value directly into the message buffer
                let (rem, variant_idx) = decompress_leb128(rem).map_err(|_| ViewError::NoData)?;

                match variant_idx {
                    0 => {
                        // Text variant - record { content: text }
                        let (_, text) = parse_text(rem).map_err(|_| ViewError::NoData)?;
                        handle_ui_message(text.as_bytes(), message, page)
                    }
                    2 => {
                        // TimestampSeconds
                        if rem.len() < 8 {
                            return Err(ViewError::NoData);
                        }
                        let (_, timestamp) = read_u64_le(rem).map_err(|_| ViewError::NoData)?;

                        // Format directly into message buffer
                        let m_len = message.len() - 1;
                        if m_len < 1 {
                            return Err(ViewError::NoData);
                        }

                        // Use a portion of the message buffer for formatting
                        let format_len = crate::utils::format_timestamp(timestamp, message)
                            .map_err(|_| ViewError::NoData)?;

                        // Null terminate
                        message[format_len] = 0;

                        // Return number of pages (always 1 for these values)
                        Ok(1)
                    }
                    3 => {
                        // DurationSeconds
                        if rem.len() < 8 {
                            return Err(ViewError::NoData);
                        }
                        let (_, duration) = read_u64_le(rem).map_err(|_| ViewError::NoData)?;

                        // Format directly into message buffer
                        let m_len = message.len() - 1;
                        if m_len < 1 {
                            return Err(ViewError::NoData);
                        }

                        // Use a portion of the message buffer for formatting
                        let format_len = crate::utils::format_duration(duration, message)
                            .map_err(|_| ViewError::NoData)?;

                        // Null terminate
                        message[format_len] = 0;

                        // Return number of pages (always 1 for these values)
                        Ok(1)
                    }
                    1 => {
                        // TokenAmount - record { decimals: u8, amount: u64, symbol: text }
                        let (rem, decimals) = read_u8(rem).map_err(|_| ViewError::NoData)?;
                        let (rem, amount) = read_u64_le(rem).map_err(|_| ViewError::NoData)?;
                        let (_, symbol) = parse_text(rem).map_err(|_| ViewError::NoData)?;

                        // Format directly into message buffer
                        let m_len = message.len() - 1;
                        if m_len < 1 {
                            return Err(ViewError::NoData);
                        }

                        // Use the message buffer for formatting
                        let format_len =
                            crate::utils::format_token_amount(amount, decimals, symbol, message)
                                .map_err(|_| ViewError::NoData)?;

                        // Null terminate
                        message[format_len] = 0;

                        // Return number of pages (always 1 for these values)
                        Ok(1)
                    }
                    _ => Err(ViewError::NoData),
                }
            }
            ConsentMessage::GenericDisplayMessage(..) => {
                // No Data as this kind of message is not supported
                Err(ViewError::Reject)
            }
        }
    }
}
