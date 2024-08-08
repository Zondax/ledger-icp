use nom::bytes::complete::{take, take_until};

use crate::{error::ParserError, utils::decompress_leb128};

/// Parse a text from the candid encoded input
pub fn parse_text(input: &[u8]) -> Result<(&[u8], &str), nom::Err<ParserError>> {
    let (rem, len) = crate::utils::decompress_leb128(input)?;
    let (rem, bytes) = take(len as usize)(rem)?;
    let s = core::str::from_utf8(bytes).map_err(|_| nom::Err::Error(ParserError::InvalidUtf8))?;

    Ok((rem, s))
}

/// Parse blob from the candid encoded input
pub fn parse_bytes(input: &[u8]) -> Result<(&[u8], &[u8]), nom::Err<ParserError>> {
    let (rem, len) = crate::utils::decompress_leb128(input)?;
    #[cfg(test)]
    std::println!("bytes_len: {}", len);
    let (rem, bytes) = take(len as usize)(rem)?;

    Ok((rem, bytes))
}

/// Parses the input to extract the DIDL-prefixed argument data
fn parse_candid_arg_slice(input: &[u8]) -> Result<(&[u8], &[u8]), nom::Err<ParserError>> {
    // Find the DIDL magic number
    let (_, didl_start) = take_until("DIDL")(input)?;

    // Extract the slice from DIDL to the end
    let arg_slice = &input[didl_start.as_ptr() as usize - input.as_ptr() as usize..];

    Ok((&[], arg_slice))
}

/// Generates parser functions for any Option<Number> from the candid encoded input
/// Number could be either a u8, ..., u64 or i8, ..., i64
/// This version is more flexible, returning None for unexpected or missing data
macro_rules! generate_opt_number {
    ($num_type:ty, $func_name:ident, $le_type:ident) => {
        pub fn $func_name(input: &[u8]) -> Result<(&[u8], Option<$num_type>), ParserError> {
            let Ok((rem, opt_tag)) =
                decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)
            else {
                return Ok((input, None));
            };

            match opt_tag {
                0 => Ok((rem, None)),
                1 => {
                    let (rem, value) = nom::number::complete::$le_type(rem)
                        .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;
                    Ok((rem, Some(value)))
                }
                _ => Ok((input, None)),
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
