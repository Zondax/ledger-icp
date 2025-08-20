use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::{
    candid_header::CandidHeader, consent_message::msg_metadata::ConsentMessageMetadata,
    error::ParserError, type_table::TypeTable, utils::decompress_leb128,
};

// type icrc21_consent_message_spec = record {
//     metadata: icrc21_consent_message_metadata;
//
//     device_spec: opt variant {
//         GenericDisplay;
//    FieldsDisplayMessage: record {
//        // Context and type of canister call, accurate and concise e.g. Send ICP
//        intent: text;
//        // Canister call fields for review e.g. Amount 234.73 ICP
//        fields: vec record { text; text };
//    };
//     };
// };
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Icrc21ConsentMessageSpec<'a> {
    pub(crate) metadata: ConsentMessageMetadata<'a>, // 2
    pub(crate) device_spec: Option<DeviceSpec<'a>>,  // 4
}

impl Icrc21ConsentMessageSpec<'_> {
    pub fn language(&self) -> &str {
        self.metadata.language
    }

    pub fn utc_offset(&self) -> Option<i16> {
        self.metadata.utc_offset
    }
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum DeviceSpec<'a> {
    FieldsDisplayMessage {
        intent: &'a str,
        fields: &'a [u8],
        field_count: u8,
    },
    GenericDisplay,
}

impl<'a> crate::FromCandidHeader<'a> for Icrc21ConsentMessageSpec<'a> {
    fn from_candid_header<const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
        header: &CandidHeader<MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("Icrc21ConsentMessageSpec::from_candid_header\x00");

        let mut rem = input;
        let mut metadata = MaybeUninit::uninit();

        // Parse metadata field (METADATA_HASH = 1075439471)
        rem = ConsentMessageMetadata::from_candid_header(rem, &mut metadata, header)?;

        // Parse optional device spec field (DEVSPEC_HASH = 2_156_826_233)
        let (new_rem, value) = parse_opt_device_spec(rem, &header.type_table)?;
        let device_spec = value;
        rem = new_rem;

        let out_ptr = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out_ptr).metadata).write(metadata.assume_init());
            addr_of_mut!((*out_ptr).device_spec).write(device_spec);
        }

        Ok(rem)
    }
}

fn parse_opt_device_spec<'a>(
    input: &'a [u8],
    _type_table: &TypeTable,
) -> Result<(&'a [u8], Option<DeviceSpec<'a>>), ParserError> {
    let (rem, has_value) = decompress_leb128(input)?;

    if has_value == 0 {
        return Ok((rem, None));
    }

    let (rem, variant_idx) = decompress_leb128(rem)?;

    match variant_idx {
        0 => {
            // Parse FieldsDisplayMessage variant
            // Note: The field order in ICRC21 spec is different from consent message
            // ICRC21 has intent first, then fields
            // First parse intent (text)
            let (rem, intent) = crate::candid_utils::parse_text(rem)?;

            // Then parse fields vector
            let (rem, field_count) = crate::utils::decompress_leb128(rem)?;

            // Store the start position of fields data
            let fields_start = rem;

            // Calculate total size of fields data
            // Each field is a record with key (text) and value (variant)
            let mut current = rem;
            for _ in 0..field_count {
                // Skip key (text)
                let (new_rem, _) = crate::candid_utils::parse_text(current)?;

                // Skip value - it's a variant, not just text
                // Read variant index
                let (new_rem, value_variant_idx) = crate::utils::decompress_leb128(new_rem)?;

                // Skip based on variant type
                // The value can be one of: Text, TimestampSeconds, DurationSeconds, TokenAmount
                let new_rem = match value_variant_idx {
                    0 => {
                        // Text variant - skip the text content
                        let (rem, _) = crate::candid_utils::parse_text(new_rem)?;
                        rem
                    }
                    1 | 2 => {
                        // TimestampSeconds or DurationSeconds - skip u64
                        if new_rem.len() < 8 {
                            return Err(ParserError::UnexpectedBufferEnd);
                        }
                        let (rem, _) = crate::utils::read_u64_le(new_rem)?;
                        rem
                    }
                    3 => {
                        // TokenAmount - skip amount (u64), decimals (u8), symbol (text)
                        let (rem, _) = crate::utils::read_u64_le(new_rem)?;
                        let (rem, _) = crate::utils::read_u8(rem)?;
                        let (rem, _) = crate::candid_utils::parse_text(rem)?;
                        rem
                    }
                    _ => return Err(ParserError::UnexpectedType),
                };

                current = new_rem;
            }

            // Calculate total size from start to current position
            let total_size = fields_start.len() - current.len();

            // Take the fields data from the correct position
            let (_fields_end, fields) = nom::bytes::complete::take(total_size)(fields_start)
                .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ParserError::UnexpectedError)?;

            Ok((
                current,
                Some(DeviceSpec::FieldsDisplayMessage {
                    intent,
                    fields,
                    field_count: field_count as u8,
                }),
            ))
        }
        1 => Ok((rem, Some(DeviceSpec::GenericDisplay))),
        _ => Err(ParserError::UnexpectedError),
    }
}
