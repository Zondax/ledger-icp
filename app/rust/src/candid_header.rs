use crate::{
    argument_list::{parse_argument_types, ArgumentTypes},
    error::ParserError,
    type_table::{parse_type_table, TypeTable},
};

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct CandidHeader<const MAX_FIELDS: usize, const MAX_ARGS: usize> {
    pub type_table: TypeTable<MAX_FIELDS>,
    pub arguments: ArgumentTypes<MAX_ARGS>,
}

impl<const MAX_FIELDS: usize, const MAX_ARGS: usize> CandidHeader<MAX_FIELDS, MAX_ARGS> {
    pub fn new(type_table: TypeTable<MAX_FIELDS>, arguments: ArgumentTypes<MAX_ARGS>) -> Self {
        Self {
            type_table,
            arguments,
        }
    }
}

pub fn parse_candid_header<const MAX_FIELDS: usize, const MAX_ARGS: usize>(
    input: &[u8],
) -> Result<(&[u8], CandidHeader<MAX_FIELDS, MAX_ARGS>), ParserError> {
    // 1. Magic number
    let (rem, _) = nom::bytes::complete::tag("DIDL")(input)
        .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;

    // 2. Type table
    let (rem, type_table) = parse_type_table(rem)?;

    #[cfg(test)]
    crate::type_table::print_type_table(&type_table);

    // 3. Argument types
    let (rem, arguments) = parse_argument_types(rem)?;

    Ok((rem, CandidHeader::new(type_table, arguments)))
}
