use core::{mem::MaybeUninit, ptr::addr_of_mut};

use nom::number::complete::le_u16;

use crate::{
    candid_header::CandidHeader, consent_message::msg_metadata::ConsentMessageMetadata,
    error::ParserError, type_table::TypeTable, utils::decompress_leb128,
};

// type icrc21_consent_message_spec = record {
//     metadata: icrc21_consent_message_metadata;
//
//     device_spec: opt variant {
//         GenericDisplay;
//         LineDisplay: record {
//             characters_per_line: nat16;
//             lines_per_page: nat16;
//         };
//     };
// };
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Icrc21ConsentMessageSpec<'a> {
    pub(crate) metadata: ConsentMessageMetadata<'a>, // 2
    pub(crate) device_spec: Option<DeviceSpec>,      // 4
}

impl<'a> Icrc21ConsentMessageSpec<'a> {
    const METADATA_HASH: u32 = 1075439471;
    const DEVSPEC_HASH: u32 = 1534901700;

    pub fn language(&self) -> &str {
        self.metadata.language
    }

    pub fn utc_offset(&self) -> Option<i16> {
        self.metadata.utc_offset
    }

    pub fn lines_per_page(&self) -> Option<u16> {
        match self.device_spec.as_ref()? {
            DeviceSpec::LineDisplay { lines_per_page, .. } => Some(*lines_per_page),
            _ => None,
        }
    }

    pub fn chars_per_line(&self) -> Option<u16> {
        match self.device_spec.as_ref()? {
            DeviceSpec::LineDisplay {
                characters_per_line,
                ..
            } => Some(*characters_per_line),
            _ => None,
        }
    }
}

// device_spec: opt variant {
//         GenericDisplay;
//         LineDisplay: record {
//             characters_per_line: nat16;
//             lines_per_page: nat16;
//         };
//     };
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum DeviceSpec {
    GenericDisplay,
    LineDisplay {
        characters_per_line: u16,
        lines_per_page: u16,
    },
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

        // Parse optional device spec field (DEVSPEC_HASH = 1534901700)
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
) -> Result<(&'a [u8], Option<DeviceSpec>), ParserError> {
    let (rem, has_value) = decompress_leb128(input)?;

    if has_value == 0 {
        return Ok((rem, None));
    }

    let (rem, variant_idx) = decompress_leb128(rem)?;

    match variant_idx {
        0 => Ok((rem, Some(DeviceSpec::GenericDisplay))),
        1 => {
            let (rem, characters_per_line) = le_u16(rem)
                .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ParserError::UnexpectedError)?;
            let (rem, lines_per_page) = le_u16(rem)
                .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ParserError::UnexpectedError)?;

            Ok((
                rem,
                Some(DeviceSpec::LineDisplay {
                    characters_per_line,
                    lines_per_page,
                }),
            ))
        }
        _ => Err(ParserError::UnexpectedError),
    }
}
