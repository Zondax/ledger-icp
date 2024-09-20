use core::{mem::MaybeUninit, ptr::addr_of_mut};

/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use minicbor::Decoder;

use crate::{constants::BLS_SIGNATURE_SIZE, error::ParserError, zlog, FromBytes};

use super::raw_value::RawValue;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Signature<'a>(&'a [u8; BLS_SIGNATURE_SIZE]);

impl<'a> Signature<'a> {
    pub fn bls_signature(&self) -> &[u8; BLS_SIGNATURE_SIZE] {
        self.0
    }
}

impl<'a> TryFrom<RawValue<'a>> for Signature<'a> {
    type Error = ParserError;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut signature = MaybeUninit::uninit();
        let _ = Signature::from_bytes_into(value.bytes(), &mut signature)?;
        Ok(unsafe { signature.assume_init() })
    }
}

impl<'a> FromBytes<'a> for Signature<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], crate::error::ParserError> {
        zlog("Signature::from_bytes\x00");

        let mut d = Decoder::new(input);
        let out = out.as_mut_ptr();

        let b = d.bytes()?;

        if b.len() != BLS_SIGNATURE_SIZE {
            return Err(ParserError::ValueOutOfRange);
        }

        unsafe {
            addr_of_mut!((*out).0).write(arrayref::array_ref!(b, 0, BLS_SIGNATURE_SIZE));
        }

        Ok(&input[d.position()..])
    }
}
