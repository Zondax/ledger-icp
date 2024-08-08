use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::{candid_types::parse_type_table, error::ParserError, FromBytes};

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

        // 2. Parse the type table
        let raw_request = parse_type_table(rem).unwrap();

        // 3. Parse message request
        let mut request = MaybeUninit::uninit();

        let rem = Icrc21ConsentMessageRequest::from_bytes_into(raw_request, &mut request)?;
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
        let raw_request = parse_type_table(rem).unwrap();

        // 3. Parse message request
        let mut request = MaybeUninit::uninit();

        Icrc21ConsentMessageRequest::from_bytes_into(raw_request, &mut request).unwrap();
        unsafe { request.assume_init() }
    }
}
#[cfg(test)]
mod test_arg {
    use super::*;

    const ARG: &str = "
4449444c076d7b6c01d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d026e036c0
2efcee7800401c4fbf2db05046c03d6fca70200e1edeb4a7184f7fee80a0501060c4449444c00017104746f626905
677265657402656e01011e000300";

    #[test]
    fn parse_arg() {
        let data = hex::decode("4449444C076D7B6C01D880C6D007716C02CBAEB581017AB183E7F1077A6B028BEABFC2067F8EF1C1EE0D026E036C02EFCEE7800401C4FBF2DB05046C03D6FCA70200E1EDEB4A7184F7FEE80A0501060C4449444C00017104746F626905677265657402656E01011E000300").unwrap();
        let arg = RawArg::from_bytes(&data).unwrap();
        std::println!("RawArg: {:?}", arg.icrc21_msg_request());
        std::println!(
            "request_id: {:?}",
            hex::encode(arg.icrc21_msg_request().request_id())
        );
    }
}
