use crate::error::ParserError;

#[repr(i32)]
#[derive(PartialEq, Copy, Clone)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum IDLTypes {
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

#[cfg(test)]
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
