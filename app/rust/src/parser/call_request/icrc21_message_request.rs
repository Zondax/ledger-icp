use core::mem::MaybeUninit;

use crate::{
    candid_header::parse_candid_header,
    candid_types::IDLTypes,
    candid_utils::{parse_bytes, parse_text},
    constants::{MAX_ARGS, MAX_TABLE_FIELDS},
    error::ParserError,
    type_table::{TypeTable, TypeTableEntry},
    zlog, FromCandidHeader,
};

use super::Icrc21ConsentMessageSpec;

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
// https://github.com/dfinity/wg-identity-authentication/blob/main/topics/ICRC-21/ICRC-21.did#L38
pub struct Icrc21ConsentMessageRequest<'a>(&'a [u8]);

enum Icrc21Field<'a> {
    Method(&'a str),
    Arg(&'a [u8]),
    UserPreferences(Icrc21ConsentMessageSpec<'a>),
}

impl<'a> Icrc21ConsentMessageRequest<'a> {
    pub const INDEX: usize = 7;
    const ARG_FIELD: u32 = 4849238;
    const METHOD_FIELD: u32 = 156956385;
    const USER_PREFERENCES_FIELD: u32 = 2904537988;

    pub(crate) fn new_unchecked(input: &'a [u8]) -> Self {
        Self(input)
    }

    // Public methods using clear names
    #[inline(never)]
    pub fn method(&self) -> Result<&str, ParserError> {
        self.get_field(Self::METHOD_FIELD)?
            .ok_or(ParserError::UnexpectedField)
            .and_then(|field| match field {
                Icrc21Field::Method(method) => Ok(method),
                _ => Err(ParserError::UnexpectedField),
            })
    }

    #[inline(never)]
    pub fn arg(&self) -> Result<&[u8], ParserError> {
        self.get_field(Self::ARG_FIELD)?
            .ok_or(ParserError::UnexpectedField)
            .and_then(|field| match field {
                Icrc21Field::Arg(arg) => Ok(arg),
                _ => Err(ParserError::UnexpectedField),
            })
    }

    #[inline(never)]
    pub fn user_preferences(&self) -> Result<Icrc21ConsentMessageSpec<'a>, ParserError> {
        self.get_field(Self::USER_PREFERENCES_FIELD)?
            .ok_or(ParserError::UnexpectedField)
            .and_then(|field| match field {
                Icrc21Field::UserPreferences(prefs) => Ok(prefs),
                _ => Err(ParserError::UnexpectedField),
            })
    }

    fn find_request_type<const MAX_FIELDS: usize>(
        table: &TypeTable<MAX_FIELDS>,
    ) -> Option<&TypeTableEntry<MAX_FIELDS>> {
        // In order to not depend on Self::INDEX
        // we can try to look at the table for the entry
        // that contains our 3 fields, method, arg and preferences
        // using their hashes.
        for i in 0..table.entry_count {
            let entry = &table.entries[i as usize];
            if entry.type_code != IDLTypes::Record {
                continue;
            }

            let mut found_arg = false;
            let mut found_method = false;
            let mut found_preferences = false;

            // Check each field in this record
            for j in 0..entry.field_count as usize {
                let (hash, _) = entry.fields[j];
                match hash {
                    h if h == Self::ARG_FIELD => found_arg = true,
                    h if h == Self::METHOD_FIELD => found_method = true,
                    h if h == Self::USER_PREFERENCES_FIELD => found_preferences = true,
                    _ => continue,
                }
            }

            // If we found all three fields, this is our record type
            if found_arg && found_method && found_preferences {
                return Some(entry);
            }
        }
        None
    }

    fn get_field(&self, field: u32) -> Result<Option<Icrc21Field<'a>>, ParserError> {
        zlog("Icrc21ConsentMessageRequest::get_field\x00");

        let (raw_request, header) = parse_candid_header::<MAX_TABLE_FIELDS, MAX_ARGS>(self.0)?;

        let entry =
            Self::find_request_type(&header.type_table).ok_or(ParserError::FieldNotFound)?;

        #[cfg(test)]
        {
            std::println!("Found request record type:");
            for (i, (hash, _field_type)) in entry
                .fields
                .iter()
                .take(entry.field_count as usize)
                .enumerate()
            {
                std::println!(
                    "Field {}: hash={}, type={:?}, matches_target={}",
                    i,
                    hash,
                    _field_type,
                    hash == &field
                );
            }
        }

        let mut rem = raw_request;

        // Fields must be parsed in order of appearance
        for i in 0..entry.field_count as usize {
            let (hash, _field_type) = entry.fields[i];

            match hash {
                Self::ARG_FIELD => {
                    let (new_rem, value) = parse_bytes(rem)?;
                    rem = new_rem;
                    if hash == field {
                        return Ok(Some(Icrc21Field::Arg(value)));
                    }
                }
                Self::METHOD_FIELD => {
                    let (new_rem, value) = parse_text(rem)?;
                    rem = new_rem;
                    if hash == field {
                        return Ok(Some(Icrc21Field::Method(value)));
                    }
                }
                Self::USER_PREFERENCES_FIELD => {
                    let mut user_preferences = MaybeUninit::uninit();
                    rem = Icrc21ConsentMessageSpec::from_candid_header(
                        rem,
                        &mut user_preferences,
                        &header,
                    )?;

                    if hash == field {
                        return Ok(Some(Icrc21Field::UserPreferences(unsafe {
                            user_preferences.assume_init()
                        })));
                    }
                }
                _ => {
                    #[cfg(test)]
                    std::println!("Unknown field hash: {}", hash);
                    continue;
                }
            };
        }

        Ok(None)
    }
}

#[cfg(test)]
mod icrc21_msg_request_test {
    use super::*;

    const ICRC21_DATA: &str =
        "4449444c086d7b6e766c02aeaeb1cc0501d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d036e046c02efcee7800402c4fbf2db05056c03d6fca70200e1edeb4a7184f7fee80a060107684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101000d69637263325f617070726f76650002656e010123000300";

    const METHOD: &str = "icrc2_approve";
    const ARGS: &str = "4449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a0000000000000007010100";
    const LANGUAGE: &str = "en";
    const LINES_PER_PAGE: u16 = 3;

    #[test]
    fn test_icrc21_msg_request() {
        let icrc = hex::decode(ICRC21_DATA).unwrap();
        let icrc = Icrc21ConsentMessageRequest::new_unchecked(&icrc);

        let method = icrc.method().unwrap();
        assert_eq!(method, METHOD);
        let arg = icrc.arg().unwrap();
        assert_eq!(hex::encode(arg), ARGS);
        let user_preferences = icrc.user_preferences().unwrap();
        assert_eq!(user_preferences.language(), LANGUAGE);
        assert_eq!(user_preferences.utc_offset(), None);
    }
}
