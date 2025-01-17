use core::ptr::addr_of_mut;

use crate::{error::ParserError, FromBytes};

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

impl RawArg<'_> {
    pub fn raw_data(&self) -> &[u8] {
        self.0
    }
}
