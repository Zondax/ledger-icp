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
use minicbor::{decode::Error, Decode, Decoder};

use crate::constants::BLS_SIGNATURE_SIZE;

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
    type Error = Error;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut d = Decoder::new(value.bytes());
        Self::decode(&mut d, &mut ())
    }
}

impl<'b, C> Decode<'b, C> for Signature<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        // Expect Bytes and ensure we have at leaste 48-bytes
        let b = d.bytes()?;
        if b.len() != BLS_SIGNATURE_SIZE {
            return Err(Error::message("Invalid BLS signature length"));
        }

        Ok(Signature(arrayref::array_ref!(b, 0, BLS_SIGNATURE_SIZE)))
    }
}
