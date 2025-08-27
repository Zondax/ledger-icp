use crate::error::ParserError;
use nom::bytes::complete::take;

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
    let (rem, bytes) = take(len as usize)(rem)?;

    Ok((rem, bytes))
}

/// Generates parser functions for any Option<Number> from the candid encoded input
/// Number could be either a u8, ..., u64 or i8, ..., i64
/// This version follows Candid spec exactly: i8(0) for None, i8(1) for Some
macro_rules! generate_opt_number {
    ($num_type:ty, $func_name:ident, $le_type:ident) => {
        pub fn $func_name(input: &[u8]) -> Result<(&[u8], Option<$num_type>), ParserError> {
            if input.is_empty() {
                return Err(ParserError::UnexpectedBufferEnd);
            }
            // Read single byte for opt tag (not leb128)
            let opt_tag = input[0];
            let rem = &input[1..];

            match opt_tag {
                0 => Ok((rem, None)),
                1 => {
                    let (rem, value) = nom::number::complete::$le_type(rem)
                        .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;
                    Ok((rem, Some(value)))
                }
                _ => Err(ParserError::UnexpectedType),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opt_i16_parser() {
        // Test None case
        let input = &[0, 0xFF, 0xFF]; // 0 followed by garbage
        let (rem, value) = parse_opt_i16(input).unwrap();
        assert_eq!(value, None);
        assert_eq!(rem, &[0xFF, 0xFF]);

        // Test Some case
        let input = &[1, 0x2A, 0x00]; // 1 followed by 42 in little endian
        let (rem, value) = parse_opt_i16(input).unwrap();
        assert_eq!(value, Some(42));
        assert!(rem.is_empty());

        // Test invalid tag
        let input = &[2, 0x00, 0x00];
        assert!(parse_opt_i16(input).is_err());
    }
}
