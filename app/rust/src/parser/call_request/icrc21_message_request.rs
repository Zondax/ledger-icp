use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::{
    candid_utils::{parse_bytes, parse_text},
    error::ParserError,
    type_table::TypeTable,
    utils::decompress_leb128,
    FromTable,
};

use super::Icrc21ConsentMessageSpec;

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Icrc21ConsentMessageRequest<'a> {
    method: &'a str,
    arg: &'a [u8],
    user_preferences: Icrc21ConsentMessageSpec<'a>,
}

impl<'a> Icrc21ConsentMessageRequest<'a> {
    pub fn preferences(&self) -> &Icrc21ConsentMessageSpec<'a> {
        &self.user_preferences
    }
    pub fn method(&self) -> &str {
        self.method
    }
    pub fn arg(&self) -> &[u8] {
        self.arg
    }

    pub fn user_preferences(&self) -> &Icrc21ConsentMessageSpec<'a> {
        &self.user_preferences
    }
}

impl<'a> FromTable<'a> for Icrc21ConsentMessageRequest<'a> {
    fn from_table(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
        type_table: &TypeTable,
        type_index: usize,
    ) -> Result<&'a [u8], ParserError> {
        let entry = type_table
            .find_type_entry(type_index)
            .ok_or(ParserError::FieldNotFound)?;

        let mut rem = input;
        let mut arg = None;
        let mut method = None;
        let mut user_preferences = MaybeUninit::uninit();

        for i in 0..entry.field_count as usize {
            let (hash, field_type) = entry.fields[i];
            match hash {
                4849238 => {
                    // arg
                    // skip type information of args
                    let (new_rem, _) = decompress_leb128(rem)?;
                    let (new_rem, _) = decompress_leb128(new_rem)?;
                    let (new_rem, value) = parse_bytes(new_rem)?;
                    arg = Some(value);
                    rem = new_rem;
                }
                156956385 => {
                    // method
                    let (new_rem, value) = parse_text(rem)?;
                    method = Some(value);
                    rem = new_rem;
                }
                2904537988 => {
                    // user_preferences
                    rem = Icrc21ConsentMessageSpec::from_table(
                        rem,
                        &mut user_preferences,
                        type_table,
                        field_type.as_index().ok_or(ParserError::FieldNotFound)?,
                    )?;
                }
                _ => return Err(ParserError::UnexpectedField),
            }
        }

        let out_ptr = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out_ptr).arg).write(arg.ok_or(ParserError::FieldNotFound)?);
            addr_of_mut!((*out_ptr).method).write(method.ok_or(ParserError::FieldNotFound)?);
            addr_of_mut!((*out_ptr).user_preferences).write(user_preferences.assume_init());
        }
        Ok(rem)
    }
}
