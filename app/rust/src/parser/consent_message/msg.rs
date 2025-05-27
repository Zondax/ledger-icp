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
    error::{ParserError, ViewError},
    utils::{decompress_leb128, handle_ui_message},
    DisplayableItem, FromCandidHeader,
};

// Constants for field hashes
const GENERIC_DISPLAY_MESSAGE_HASH: u32 = 4082495484;
const FIELDS_DISPLAY_HASH: u32 = 124612638;
const FIELDS_HASH: u32 = 2156826233;
const INTENT_HASH: u32 = 2659612252;

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

impl<'a> ConsentMessage<'a> {
    // Extract the nth field (key-value pair) from fields data
    fn get_field(&self, field_index: u8) -> Result<(&'a str, &'a str), ParserError> {
        match self {
            ConsentMessage::FieldsDisplayMessage {
                fields,
                field_count,
                ..
            } => {
                if field_index >= *field_count {
                    return Err(ParserError::ValueOutOfRange);
                }

                let mut current = *fields;

                // Skip to the desired field
                for _ in 0..field_index {
                    // Skip key
                    let (rem, _) = parse_text(current)?;
                    // Skip value
                    let (rem, _) = parse_text(rem)?;
                    current = rem;
                }

                // Parse the target field
                let (rem, key) = parse_text(current)?;
                let (_, value) = parse_text(rem)?;

                Ok((key, value))
            }
            _ => Err(ParserError::UnexpectedType),
        }
    }
}

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
    fn from_candid_header<const TABLE_SIZE: usize, const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<TABLE_SIZE, MAX_ARGS>,
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
                    addr_of_mut!((*out).num_items).write(*field_count);
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

impl<'a> FromCandidHeader<'a> for ConsentMessage<'a> {
    fn from_candid_header<const TABLE_SIZE: usize, const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<TABLE_SIZE, MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("ConsentMessage::from_candid_header\x00");

        // Read variant index
        let (rem, variant_index) = decompress_leb128(input)?;

        // Get type info from table
        let type_entry = header
            .type_table
            .find_type_entry(5)
            .ok_or(ParserError::UnexpectedType)?;

        if variant_index >= type_entry.field_count as u64 {
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
                    .find_type_entry(6)
                    .ok_or(ParserError::UnexpectedType)?;

                // Parse fields vector first (FIELDS_HASH = 2156826233)
                let _ = record_entry
                    .fields
                    .iter()
                    .find(|(hash, _)| *hash == FIELDS_HASH)
                    .ok_or(ParserError::UnexpectedType)?;

                // Get the vector length (number of records)
                let (rem, field_count) = decompress_leb128(rem)?;

                // Calculate size of each record and total size
                let mut current = rem;
                let mut total_size = 0;
                for _ in 0..field_count {
                    // Skip key
                    let (rem, _) = parse_text(current)?;
                    // Skip value
                    let (rem, _) = parse_text(rem)?;
                    total_size += current.len() - rem.len();
                    current = rem;
                }

                // Take only the fields content
                let (rem, fields) = take(total_size)(rem)?;

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
            ConsentMessage::FieldsDisplayMessage { field_count, .. } => Ok(*field_count),
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
        let title_bytes = b"ConsentMsg";
        let title_len = title_bytes.len().min(title.len() - 1);
        title[..title_len].copy_from_slice(&title_bytes[..title_len]);
        title[title_len] = 0;

        match self {
            ConsentMessage::FieldsDisplayMessage { .. } => {
                // Get the field for this item
                let (key, value) = self.get_field(item_n).map_err(|_| ViewError::NoData)?;

                // Set the title to the key
                let key_bytes = key.as_bytes();
                let key_len = key_bytes.len().min(title.len() - 1);
                title[..key_len].copy_from_slice(&key_bytes[..key_len]);
                title[key_len] = 0;

                // Set the message to the value
                handle_ui_message(value.as_bytes(), message, page)
            }
            ConsentMessage::GenericDisplayMessage(..) => {
                // No Data as this kind of message is not supported
                Err(ViewError::Reject)
            }
        }
    }
}
