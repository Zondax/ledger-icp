use nom::bytes::complete::take;

use crate::{error::ParserError, utils::decompress_leb128};

/// Parse a text from the candid encoded input
pub fn parse_text(input: &[u8]) -> Result<(&[u8], &str), nom::Err<ParserError>> {
    let (rem, len) = crate::utils::decompress_leb128(input)?;
    let (rem, bytes) = take(len as usize)(rem)?;
    let s = core::str::from_utf8(bytes).map_err(|_| nom::Err::Error(ParserError::InvalidUtf8))?;

    Ok((rem, s))
}

/// Generates parser functions for any Option<Number> from the candid encoded input
/// Number could be either a u8, ..., u64 or i8, ..., i64
macro_rules! generate_opt_number {
    ($num_type:ty, $func_name:ident, $le_type:ident) => {
        pub fn $func_name(input: &[u8]) -> Result<(&[u8], Option<$num_type>), ParserError> {
            let (rem, opt_tag) =
                decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;
            match opt_tag {
                0 => Ok((rem, None)),
                1 => {
                    let (rem, value) = nom::number::complete::$le_type(rem)
                        .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;
                    Ok((rem, Some(value)))
                }
                _ => Err(ParserError::UnexpectedValue),
            }
        }
    };
}

// Generate functions for unsigned integers
generate_opt_number!(u8, parse_opt_u8, le_u8);
generate_opt_number!(u16, parse_opt_u16, le_u16);
generate_opt_number!(u32, parse_opt_u32, le_u32);
generate_opt_number!(u64, parse_opt_u64, le_u64);

generate_opt_number!(i8, parse_opt_i8, le_i8);
generate_opt_number!(i16, parse_opt_i16, le_i16);
generate_opt_number!(i32, parse_opt_i32, le_i32);
generate_opt_number!(i64, parse_opt_i64, le_i64);
