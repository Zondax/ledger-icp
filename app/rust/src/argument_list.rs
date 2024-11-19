use crate::{
    error::ParserError,
    utils::{decompress_leb128, decompress_sleb128},
};

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
#[derive(Clone, Copy)]
pub struct ArgumentTypes<const MAX_ARGS: usize> {
    // Could be either primitive type (negative) or type table index (positive)
    pub types: [i64; MAX_ARGS],
    pub count: u8,
}

impl<const MAX_ARGS: usize> ArgumentTypes<MAX_ARGS> {
    pub fn new() -> Self {
        Self {
            types: [0; MAX_ARGS],
            count: 0,
        }
    }

    pub fn find_type(&self, index: usize) -> Option<i64> {
        if index < self.count as usize {
            Some(self.types[index])
        } else {
            None
        }
    }
}

impl<const MAX_ARGS: usize> Default for ArgumentTypes<MAX_ARGS> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_argument_types<const MAX_ARGS: usize>(
    input: &[u8],
) -> Result<(&[u8], ArgumentTypes<MAX_ARGS>), ParserError> {
    let (rem, arg_count) = decompress_leb128(input)?;
    #[cfg(test)]
    std::println!("arg_count: {}", arg_count);
    if arg_count > MAX_ARGS as u64 {
        return Err(ParserError::TooManyTypes);
    }

    let mut args = ArgumentTypes::new();
    args.count = arg_count as u8;

    let mut current = rem;
    for i in 0..arg_count {
        let (new_rem, type_code) = decompress_sleb128(current)?;
        args.types[i as usize] = type_code;
        current = new_rem;
    }

    Ok((current, args))
}
