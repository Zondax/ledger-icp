use core::mem::MaybeUninit;

use crate::{
    candid_utils::{parse_bytes, parse_text},
    error::ParserError,
    type_table::parse_type_table,
    utils::decompress_leb128,
    zlog, FromTable,
};

use super::Icrc21ConsentMessageSpec;

// The minimun size of the candid table
// in order to parse a icrc21 message
// and inner types
const MAX_TABLE_FIELDS: usize = 7;

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Icrc21ConsentMessageRequest<'a>(&'a [u8]);

enum Icrc21Field<'a> {
    Method(&'a str),
    Arg(&'a [u8]),
    UserPreferences(Icrc21ConsentMessageSpec<'a>),
}

impl<'a> Icrc21ConsentMessageRequest<'a> {
    pub const INDEX: usize = 6;
    const ARG_FIELD: u32 = 4849238;
    const METHOD_FIELD: u32 = 156956385;
    const USER_PREFERENCES_FIELD: u32 = 2904537988;

    pub fn new_unchecked(input: &'a [u8]) -> Self {
        Self(input)
    }

    fn get_field(&self, field: u32) -> Result<Option<Icrc21Field<'a>>, ParserError> {
        zlog("get_field\x00");
        let (raw_request, table) = parse_type_table::<MAX_TABLE_FIELDS>(self.0)?;

        let entry = table
            .find_type_entry(Self::INDEX)
            .ok_or(ParserError::FieldNotFound)?;

        let mut rem = raw_request;

        for i in 0..entry.field_count as usize {
            let (hash, field_type) = entry.fields[i];
            match hash {
                4849238 => {
                    // arg
                    // skip type information of args
                    let (new_rem, _) = decompress_leb128(rem)?;
                    let (new_rem, _) = decompress_leb128(new_rem)?;
                    let (new_rem, value) = parse_bytes(new_rem)?;
                    rem = new_rem;
                    if hash == field {
                        return Ok(Some(Icrc21Field::Arg(value)));
                    }
                }
                156956385 => {
                    // method
                    let (new_rem, value) = parse_text(rem)?;
                    rem = new_rem;
                    if hash == field {
                        return Ok(Some(Icrc21Field::Method(value)));
                    }
                }
                2904537988 => {
                    // user_preferences
                    let mut user_preferences = MaybeUninit::uninit();

                    rem = Icrc21ConsentMessageSpec::from_table::<MAX_TABLE_FIELDS>(
                        rem,
                        &mut user_preferences,
                        &table,
                        field_type.as_index().ok_or(ParserError::FieldNotFound)?,
                    )?;

                    if hash == field {
                        let user = unsafe { user_preferences.assume_init() };
                        return Ok(Some(Icrc21Field::UserPreferences(user)));
                    }
                }
                _ => return Err(ParserError::UnexpectedField),
            }
        }
        Ok(None)
    }

    pub fn method(&self) -> Result<&str, ParserError> {
        let field = self
            .get_field(Self::METHOD_FIELD)?
            .ok_or(ParserError::UnexpectedField)?;
        let Icrc21Field::Method(method) = field else {
            return Err(ParserError::UnexpectedField);
        };
        Ok(method)
    }
    pub fn arg(&self) -> Result<&[u8], ParserError> {
        let field = self
            .get_field(Self::ARG_FIELD)?
            .ok_or(ParserError::UnexpectedField)?;
        let Icrc21Field::Arg(arg) = field else {
            return Err(ParserError::UnexpectedField);
        };
        Ok(arg)
    }

    pub fn user_preferences(&self) -> Result<Icrc21ConsentMessageSpec<'a>, ParserError> {
        let field = self
            .get_field(Self::USER_PREFERENCES_FIELD)?
            .ok_or(ParserError::UnexpectedField)?;
        let Icrc21Field::UserPreferences(user) = field else {
            return Err(ParserError::UnexpectedField);
        };
        Ok(user)
    }
}

// impl<'a> FromTable<'a> for Icrc21ConsentMessageRequest<'a> {
//     #[inline(never)]
//     fn from_table(
//         input: &'a [u8],
//         out: &mut MaybeUninit<Self>,
//         type_table: &TypeTable,
//         type_index: usize,
//     ) -> Result<&'a [u8], ParserError> {
//         let entry = type_table
//             .find_type_entry(type_index)
//             .ok_or(ParserError::FieldNotFound)?;
//
//         let out_ptr = out.as_mut_ptr();
//
//         let mut rem = input;
//
//         for i in 0..entry.field_count as usize {
//             let (hash, field_type) = entry.fields[i];
//             match hash {
//                 4849238 => {
//                     // arg
//                     // skip type information of args
//                     let (new_rem, _) = decompress_leb128(rem)?;
//                     let (new_rem, _) = decompress_leb128(new_rem)?;
//                     let (new_rem, value) = parse_bytes(new_rem)?;
//                     unsafe {
//                         addr_of_mut!((*out_ptr).arg).write(value);
//                     }
//                     rem = new_rem;
//                 }
//                 156956385 => {
//                     // method
//                     let (new_rem, value) = parse_text(rem)?;
//                     unsafe {
//                         addr_of_mut!((*out_ptr).method).write(value);
//                     }
//                     rem = new_rem;
//                 }
//                 2904537988 => {
//                     // user_preferences
//                     let user_preferences: &mut MaybeUninit<Icrc21ConsentMessageSpec<'a>> =
//                         unsafe { &mut *addr_of_mut!((*out_ptr).user_preferences).cast() };
//
//                     rem = Icrc21ConsentMessageSpec::from_table(
//                         rem,
//                         user_preferences,
//                         type_table,
//                         field_type.as_index().ok_or(ParserError::FieldNotFound)?,
//                     )?;
//                 }
//                 _ => return Err(ParserError::UnexpectedField),
//             }
//         }
//         Ok(rem)
//     }
// }
