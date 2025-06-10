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
    const METADATA_HASH: u32 = 1075439471;
    const DEVSPEC_HASH: u32 = 1534901700;

    pub fn language(&self) -> &str {
        self.metadata.language
    }

    pub fn utc_offset(&self) -> Option<i16> {
        self.metadata.utc_offset
    }
}

// device_spec: opt variant {
//         GenericDisplay;
//         FieldsDisplayMessage: record {
//          // Context and type of canister call, accurate and concise e.g. Send ICP
//          intent: text;
//          // Canister call fields for review e.g. Amount 234.73 ICP
//          fields: vec record { text; text };
//          };
//     };
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
    fn from_candid_header<const TABLE_SIZE: usize, const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
        header: &CandidHeader<TABLE_SIZE, MAX_ARGS>,
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

fn parse_opt_device_spec<'a, const MAX_FIELDS: usize>(
    input: &'a [u8],
    _type_table: &TypeTable<MAX_FIELDS>,
) -> Result<(&'a [u8], Option<DeviceSpec<'a>>), ParserError> {
    let (rem, has_value) = decompress_leb128(input)?;

    if has_value == 0 {
        return Ok((rem, None));
    }

    let (rem, variant_idx) = decompress_leb128(rem)?;

    match variant_idx {
        0 => {
            // Parse FieldsDisplayMessage variant
            // First parse intent (text)
            let (rem, intent) = crate::candid_utils::parse_text(rem)?;

            // Then parse fields vector
            let (rem, field_count) = crate::utils::decompress_leb128(rem)?;

            // Calculate total size of fields data
            let mut current = rem;
            let mut total_size = 0;
            for _ in 0..field_count {
                // Skip key
                let (new_rem, _) = crate::candid_utils::parse_text(current)?;
                // Skip value
                let (new_rem, _) = crate::candid_utils::parse_text(new_rem)?;
                total_size += current.len() - new_rem.len();
                current = new_rem;
            }

            // Take the fields data
            let (rem, fields) = nom::bytes::complete::take(total_size)(rem)
                .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ParserError::UnexpectedError)?;

            Ok((
                rem,
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
