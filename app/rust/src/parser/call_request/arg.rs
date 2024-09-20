use core::ptr::addr_of_mut;

use crate::{error::ParserError, FromBytes};

use super::Icrc21ConsentMessageRequest;

#[derive(PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct RawArg<'a>(&'a [u8]);

impl<'a> FromBytes<'a> for RawArg<'a> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("RawArg::from_bytes\x00");
        let out = out.as_mut_ptr();

        // store raw data which can be parsed later on demand
        // at this point we can be sure it will be parsed correctly
        unsafe {
            // skip tag
            addr_of_mut!((*out).0).write(input);
        }

        // store request bytes only
        Ok(&input[input.len()..])
    }
}

impl<'a> RawArg<'a> {
    pub fn raw_data(&self) -> &[u8] {
        self.0
    }

    pub fn icrc21_msg_request(&self) -> Result<Icrc21ConsentMessageRequest, ParserError> {
        // 1. Read the "DIDL" magic number
        let (rem, _) = nom::bytes::complete::tag("DIDL")(self.0)
            .map_err(|_: nom::Err<ParserError>| ParserError::UnexpectedError)?;

        // lazy parsing on demand in order to reduce stack usage
        Ok(Icrc21ConsentMessageRequest::new_unchecked(rem))
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
        let msg_request = arg.icrc21_msg_request().unwrap();
        std::println!("{:?}", msg_request);

        assert_eq!(msg_request.method().unwrap(), METHOD);
        assert_eq!(msg_request.arg().unwrap(), REQUEST_ARG);

        let preferences = msg_request.user_preferences().unwrap();

        assert_eq!(preferences.chars_per_line(), Some(CHARS_PER_LINE));
        assert_eq!(preferences.lines_per_page(), Some(PAGE_LINES));
    }
}
