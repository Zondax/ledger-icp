use core::{mem::MaybeUninit, ptr::addr_of_mut};

use nom::number::complete::le_u16;

use crate::{error::ParserError, type_table::TypeTable, utils::decompress_leb128, FromTable};

use super::Icrc21ConsentMessageMetadata;

type Hash256 = [u8; 32];

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Icrc21ConsentMessageSpec<'a> {
    metadata: Icrc21ConsentMessageMetadata<'a>, // 2
    device_spec: Option<DeviceSpec>,            // 4
}

impl<'a> Icrc21ConsentMessageSpec<'a> {
    pub fn language(&self) -> &str {
        self.metadata.language
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
//         // A generic display able to handle large documents and do line wrapping and pagination / scrolling.
//         // Text must be Markdown formatted, no external resources (e.g. images) are allowed.
//         GenericDisplay;
//         // Simple display able to handle lines of text with a maximum number of characters per line.
//         // Multiple pages can be used if the text does no fit on a single page.
//         // Text must be plain text without any embedded formatting elements.
//         LineDisplay: record {
//             // Maximum number of characters that can be displayed per line.
//             characters_per_line: nat16;
//             // Maximum number of lines that can be displayed at once on a single page.
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

impl<'a> FromTable<'a> for Icrc21ConsentMessageSpec<'a> {
    #[inline(never)]
    fn from_table<const MAX_FIELDS: usize>(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
        type_table: &TypeTable<MAX_FIELDS>,
        type_index: usize,
    ) -> Result<&'a [u8], ParserError> {
        let entry = type_table
            .find_type_entry(type_index)
            .ok_or(ParserError::FieldNotFound)?;

        let mut rem = input;
        let mut metadata = MaybeUninit::uninit();
        let mut device_spec = None;

        for i in 0..entry.field_count as usize {
            let (hash, field_type) = entry.fields[i];
            match hash {
                1075439471 => {
                    // metadata

                    rem = Icrc21ConsentMessageMetadata::from_table(
                        rem,
                        &mut metadata,
                        type_table,
                        field_type.as_index().ok_or(ParserError::FieldNotFound)?,
                    )?;
                }
                1534901700 => {
                    // device_spec
                    let index = field_type.as_index().ok_or(ParserError::FieldNotFound)?;
                    let (value, new_rem) = parse_opt_device_spec(rem, type_table, index)?;
                    device_spec = value;
                    rem = new_rem;
                }
                _ => return Err(ParserError::UnexpectedField),
            }
        }

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
    _type_index: usize,
) -> Result<(Option<DeviceSpec>, &'a [u8]), ParserError> {
    let (rem, opt_tag) = decompress_leb128(input)?;

    match opt_tag {
        0 => Ok((None, rem)),
        1 => {
            let (rem, variant_tag) = decompress_leb128(rem)?;

            match variant_tag {
                0 => Ok((Some(DeviceSpec::GenericDisplay), rem)),
                1 => {
                    let (rem, characters_per_line) =
                        le_u16(rem).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
                            ParserError::UnexpectedError
                        })?;
                    let (rem, lines_per_page) =
                        le_u16(rem).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
                            ParserError::UnexpectedError
                        })?;

                    Ok((
                        Some(DeviceSpec::LineDisplay {
                            characters_per_line,
                            lines_per_page,
                        }),
                        rem,
                    ))
                }
                _ => Err(ParserError::UnexpectedError),
            }
        }
        _ => Err(ParserError::UnexpectedError),
    }
}
