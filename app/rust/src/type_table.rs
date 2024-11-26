use crate::{
    candid_types::IDLTypes,
    error::ParserError,
    utils::{decompress_leb128, decompress_sleb128},
};

// Only for debug information in testing
#[cfg(test)]
use std::{format, print, println, string::String, string::ToString};

const MAX_NUM_FIELDS: usize = 16;

#[derive(Clone, Copy)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum FieldType {
    Primitive(IDLTypes),
    Compound(usize), // Index into the type table
}

impl FieldType {
    pub fn as_index(&self) -> Option<usize> {
        match self {
            FieldType::Compound(index) => Some(*index),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct TypeTableEntry<const MAX_FIELDS: usize> {
    pub type_code: IDLTypes,
    pub fields: [(u32, FieldType); MAX_FIELDS],
    pub field_count: u8,
}

impl<const MAX_FIELDS: usize> TypeTableEntry<MAX_FIELDS> {
    pub fn find_field_type(&self, field_hash: u32) -> Result<FieldType, ParserError> {
        self.fields
            .iter()
            .take(self.field_count as usize)
            .find(|(hash, _)| *hash == field_hash)
            .map(|(_, field_type)| *field_type)
            .ok_or(ParserError::FieldNotFound)
    }
}

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
#[derive(Clone, Copy)]
pub struct TypeTable<const MAX_FIELDS: usize> {
    pub entries: [TypeTableEntry<MAX_FIELDS>; MAX_FIELDS], // Assuming max 16 types in the table
    pub entry_count: u8,
}

impl<const MAX_FIELDS: usize> TypeTable<MAX_FIELDS> {
    pub fn find_type_entry(&self, type_index: usize) -> Option<&TypeTableEntry<MAX_FIELDS>> {
        self.entries.get(type_index)
    }
    pub fn find_variant(&self, field_hash: u32) -> Result<u64, ParserError> {
        // Get the root variant entry (type 0)
        let root_entry = self.find_type_entry(0).ok_or(ParserError::UnexpectedType)?;

        match root_entry.find_field_type(field_hash)? {
            FieldType::Compound(idx) => Ok(idx as u64),
            _ => Err(ParserError::UnexpectedType),
        }
    }
}

pub fn parse_type_table<const MAX_FIELDS: usize>(
    input: &[u8],
) -> Result<(&[u8], TypeTable<MAX_FIELDS>), ParserError> {
    let (rem, type_count) = decompress_leb128(input).map_err(|_| ParserError::UnexpectedError)?;
    if type_count > MAX_FIELDS as u64 {
        return Err(ParserError::TooManyTypes);
    }

    let mut type_table = TypeTable {
        entries: [TypeTableEntry {
            type_code: IDLTypes::Null,
            fields: [(0, FieldType::Primitive(IDLTypes::Null)); MAX_FIELDS],
            field_count: 0,
        }; MAX_FIELDS],
        entry_count: type_count as u8,
    };

    let mut current = rem;

    for i in 0..type_count {
        let (new_rem, type_code) = decompress_sleb128(current)?;
        let type_code = IDLTypes::try_from(type_code)?;
        current = new_rem;

        let mut entry = TypeTableEntry {
            type_code,
            fields: [(0, FieldType::Primitive(IDLTypes::Null)); MAX_FIELDS],
            field_count: 0,
        };

        match type_code {
            IDLTypes::Opt => {
                let (new_rem, inner_type) = decompress_sleb128(current)?;
                entry.fields[0] = (0, FieldType::Compound(inner_type as usize));
                entry.field_count = 1;
                current = new_rem;
            }
            IDLTypes::Vector => {
                let (new_rem, inner_type) = decompress_sleb128(current)?;
                entry.fields[0] = (0, FieldType::Compound(inner_type as usize));
                entry.field_count = 1;
                current = new_rem;
            }
            IDLTypes::Record | IDLTypes::Variant => {
                let (new_rem, field_count) =
                    decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                if field_count > MAX_FIELDS as u64 {
                    return Err(ParserError::TooManyFields);
                }
                current = new_rem;
                for j in 0..field_count {
                    let (new_rem, field_hash) =
                        decompress_leb128(current).map_err(|_| ParserError::UnexpectedError)?;
                    let (new_rem, field_type) = decompress_sleb128(new_rem)?;
                    current = new_rem;
                    entry.fields[j as usize] =
                        (field_hash as u32, FieldType::Compound(field_type as usize));
                }
                entry.field_count = field_count as u8;
            }
            _ => {}
        };

        type_table.entries[i as usize] = entry;
    }

    Ok((current, type_table))
}

#[cfg(test)]
pub fn print_type_table<const N: usize>(type_table: &TypeTable<N>) {
    println!("Type table:");
    for (i, entry) in type_table
        .entries
        .iter()
        .enumerate()
        .take(type_table.entry_count as usize)
    {
        print!("{}: ", i);
        match entry.type_code {
            IDLTypes::Vector => println!("vec {}", print_field_type(entry.fields[0].1)),
            IDLTypes::Opt => println!("opt {}", print_field_type(entry.fields[0].1)),
            IDLTypes::Record => {
                print!("record {{");
                for j in 0..entry.field_count {
                    let (hash, field_type) = entry.fields[j as usize];
                    print!("{}: {}", hash, print_field_type(field_type));
                    if j < entry.field_count - 1 {
                        print!(", ");
                    }
                }
                println!("}}");
            }
            IDLTypes::Variant => {
                print!("variant {{");
                for j in 0..entry.field_count {
                    let (hash, field_type) = entry.fields[j as usize];
                    print!("{}: {}", hash, print_field_type(field_type));
                    if j < entry.field_count - 1 {
                        print!(", ");
                    }
                }
                println!("}}");
            }
            _ => println!("{}", entry.type_code),
        }
    }
}

#[cfg(test)]
fn print_field_type(field_type: FieldType) -> String {
    match field_type {
        FieldType::Primitive(t) => format!("{}", t as i8),
        FieldType::Compound(t) => t.to_string(),
    }
}
