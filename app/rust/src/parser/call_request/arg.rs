use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::{error::ParserError, type_table::parse_type_table, FromBytes, FromTable};

use super::Icrc21ConsentMessageRequest;

#[derive(PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct RawArg<'a>(&'a [u8]);

impl<'a> FromBytes<'a> for RawArg<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("RawArg::from_bytes_into");

        // 1. Read the "DIDL" magic number
        let (rem, _) = nom::bytes::complete::tag("DIDL")(input)
            .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;

        let (raw_request, table) = parse_type_table(rem)?;

        // 3. Parse message request
        let mut request = MaybeUninit::uninit();

        let rem = Icrc21ConsentMessageRequest::from_table(raw_request, &mut request, &table, 6)?;
        let out = out.as_mut_ptr();

        let len = input.len() - rem.len();

        // store raw data which can be parsed later on demand
        // at this point we can be sure it will be parsed correctly
        unsafe {
            // skip tag
            addr_of_mut!((*out).0).write(&input[..len]);
        }

        // store request bytes only
        Ok(rem)
    }
}

impl<'a> RawArg<'a> {
    pub fn raw_data(&self) -> &[u8] {
        self.0
    }

    pub fn icrc21_msg_request(&self) -> Icrc21ConsentMessageRequest {
        // 1. Read the "DIDL" magic number
        let (rem, _) = nom::bytes::complete::tag("DIDL")(self.0)
            .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)
            .unwrap();

        // 2. Parse the type table
        let (raw_request, table) = parse_type_table(rem).unwrap();

        // 3. Parse message request
        let mut request = MaybeUninit::uninit();

        Icrc21ConsentMessageRequest::from_table(raw_request, &mut request, &table, 6).unwrap();
        unsafe { request.assume_init() }
    }
}
#[cfg(test)]
mod test_arg {
    use super::*;

    const ARG: &str = "4449444c076d7b6c01d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d026e036c02efcee7800401c4fbf2db05046c03d6fca70200e1edeb4a7184f7fee80a0501060c4449444c00017104746f626905677265657402656e01011e000300";
    const REQUEST_ARG: &[u8] = &[68, 73, 68, 76, 0, 1, 113, 4, 116, 111, 98, 105];
    const METHOD: &str = "greet";
    const CHARS_PER_LINE: u16 = 30;
    const PAGE_LINES: u16 = 3;

    #[test]
    fn parse_arg() {
        let data = hex::decode(ARG).unwrap();
        let arg = RawArg::from_bytes(&data).unwrap();
        let msg_request = arg.icrc21_msg_request();
        std::println!("{:?}", msg_request);

        let preferences = msg_request.user_preferences();

        assert_eq!(preferences.chars_per_line(), Some(CHARS_PER_LINE));
        assert_eq!(preferences.lines_per_page(), Some(PAGE_LINES));
        assert_eq!(msg_request.method(), METHOD);
        assert_eq!(msg_request.arg(), REQUEST_ARG);
    }
}
