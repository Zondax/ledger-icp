use crate::{
    error::ParserError,
    utils::{decompress_leb128, decompress_sleb128},
};
#[cfg(test)]
use std::{string::String, vec::Vec};

#[repr(i32)]
enum IDLTypes {
    Null = -1,
    Bool = -2,
    Nat = -3,
    Int = -4,

    Nat8 = -5,
    Nat16 = -6,
    Nat32 = -7,
    Nat64 = -8,

    Int8 = -9,
    Int16 = -10,
    Int32 = -11,
    Int64 = -12,

    Float32 = -13,
    Float64 = -14,
    Text = -15,
    Reserved = -16,
    Empty = -17,
    Opt = -18,
    Vector = -19,
    Record = -20,
    Variant = -21,
    Func = -22,
    Service = -23,
    Principal = -24,
}

impl TryFrom<i64> for IDLTypes {
    type Error = ParserError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            -1 => Ok(IDLTypes::Null),
            -2 => Ok(IDLTypes::Bool),
            -3 => Ok(IDLTypes::Nat),
            -4 => Ok(IDLTypes::Int),
            -5 => Ok(IDLTypes::Nat8),
            -6 => Ok(IDLTypes::Nat16),
            -7 => Ok(IDLTypes::Nat32),
            -8 => Ok(IDLTypes::Nat64),
            -9 => Ok(IDLTypes::Int8),
            -10 => Ok(IDLTypes::Int16),
            -11 => Ok(IDLTypes::Int32),
            -12 => Ok(IDLTypes::Int64),
            -13 => Ok(IDLTypes::Float32),
            -14 => Ok(IDLTypes::Float64),
            -15 => Ok(IDLTypes::Text),
            -16 => Ok(IDLTypes::Reserved),
            -17 => Ok(IDLTypes::Empty),
            -18 => Ok(IDLTypes::Opt),
            -19 => Ok(IDLTypes::Vector),
            -20 => Ok(IDLTypes::Record),
            -21 => Ok(IDLTypes::Variant),
            -22 => Ok(IDLTypes::Func),
            -23 => Ok(IDLTypes::Service),
            -24 => Ok(IDLTypes::Principal),
            _ => Err(ParserError::UnexpectedType),
        }
    }
}

impl core::fmt::Display for IDLTypes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            IDLTypes::Null => "Null",
            IDLTypes::Bool => "Bool",
            IDLTypes::Nat => "Nat",
            IDLTypes::Int => "Int",
            IDLTypes::Nat8 => "Nat8",
            IDLTypes::Nat16 => "Nat16",
            IDLTypes::Nat32 => "Nat32",
            IDLTypes::Nat64 => "Nat64",
            IDLTypes::Int8 => "Int8",
            IDLTypes::Int16 => "Int16",
            IDLTypes::Int32 => "Int32",
            IDLTypes::Int64 => "Int64",
            IDLTypes::Float32 => "Float32",
            IDLTypes::Float64 => "Float64",
            IDLTypes::Text => "Text",
            IDLTypes::Reserved => "Reserved",
            IDLTypes::Empty => "Empty",
            IDLTypes::Opt => "Opt",
            IDLTypes::Vector => "Vector",
            IDLTypes::Record => "Record",
            IDLTypes::Variant => "Variant",
            IDLTypes::Func => "Func",
            IDLTypes::Service => "Service",
            IDLTypes::Principal => "Principal",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
fn print_table(table: &[std::string::String]) {
    std::println!("Type table:");
    for (i, t) in table.iter().enumerate() {
        std::println!("{}: {}", i, t);
    }
}

#[cfg(test)]
pub fn print_type_table(input: &[u8]) -> Result<&[u8], ParserError> {
    let (rem, type_count) = decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;
    std::println!("type_count: {}", type_count);
    let mut types = Vec::new();
    let mut current = rem;

    for _ in 0..type_count {
        let (new_rem, type_code) = decompress_sleb128(current)?;
        let type_code = IDLTypes::try_from(type_code).map_err(|_| ParserError::UnexpectedType)?;
        current = new_rem;

        let type_name = match type_code {
            IDLTypes::Opt => {
                let (new_rem, inner_type) = decompress_sleb128(current)?;
                current = new_rem;
                std::format!("opt {}", inner_type)
            }
            IDLTypes::Vector => {
                let (new_rem, inner_type) = decompress_sleb128(current)?;
                current = new_rem;
                std::format!("vec {}", inner_type)
            }
            IDLTypes::Record => {
                let (new_rem, field_count) =
                    decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                current = new_rem;
                let mut fields = Vec::new();
                for _ in 0..field_count {
                    let (new_rem, field_hash) =
                        decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                    let (new_rem, field_type) = decompress_sleb128(new_rem)?;
                    current = new_rem;
                    fields.push(std::format!("{}: {}", field_hash, field_type));
                }
                std::format!("record {{{}}}", fields.join(", "))
            }
            IDLTypes::Variant => {
                let (new_rem, field_count) =
                    decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                std::println!("variant_field_count: {}", field_count);
                current = new_rem;
                let mut fields = Vec::new();
                for _ in 0..field_count {
                    let (new_rem, field_hash) =
                        decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                    let (new_rem, field_type) = decompress_sleb128(new_rem)?;
                    current = new_rem;
                    fields.push(std::format!("{}: {}", field_hash, field_type));
                }
                std::format!("variant {{{}}}", fields.join(", "))
            }
            _ => std::format!("{}", type_code),
        };

        types.push(type_name);
    }

    #[cfg(test)]
    print_table(&types);

    Ok(current)
}

pub fn parse_type_table(input: &[u8]) -> Result<&[u8], ParserError> {
    let (rem, type_count) = decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;
    let mut current = rem;

    for _ in 0..type_count {
        let (new_rem, type_code) = decompress_sleb128(current)?;
        let type_code = IDLTypes::try_from(type_code).map_err(|_| ParserError::UnexpectedType)?;
        current = new_rem;

        match type_code {
            IDLTypes::Opt => {
                let (new_rem, _) = decompress_sleb128(current)?;
                current = new_rem;
            }
            IDLTypes::Vector => {
                let (new_rem, _) = decompress_sleb128(current)?;
                current = new_rem;
            }
            IDLTypes::Record => {
                let (new_rem, field_count) =
                    decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                current = new_rem;
                for _ in 0..field_count {
                    let (new_rem, _) =
                        decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                    let (new_rem, _) = decompress_sleb128(new_rem)?;
                    current = new_rem;
                }
            }
            IDLTypes::Variant => {
                let (new_rem, field_count) =
                    decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                current = new_rem;
                for _ in 0..field_count {
                    let (new_rem, _) =
                        decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                    let (new_rem, _) = decompress_sleb128(new_rem)?;
                    current = new_rem;
                }
            }
            _ => {}
        };
    }

    Ok(current)
}
