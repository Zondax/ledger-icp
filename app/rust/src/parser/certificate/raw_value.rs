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
use core::ptr::addr_of_mut;
use minicbor::{decode::Error, Decode, Decoder};

use crate::{zlog, FromBytes};

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct RawValue<'a>(pub(crate) &'a [u8]);

impl<'a> RawValue<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> FromBytes<'a> for RawValue<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], crate::error::ParserError> {
        zlog("RawValue::from_bytes_into\x00");

        let mut d = Decoder::new(input);

        let start = d.position();
        d.skip()?;
        let end = d.position();

        let out = out.as_mut_ptr();
        unsafe { addr_of_mut!((*out).0).write(&d.input()[start..end]) };

        Ok(&input[end..])
    }
}

// Keep Decode implementation for use
// in context where parsing is lazy
impl<'b, C> Decode<'b, C> for RawValue<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, Error> {
        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(RawValue(&d.input()[start..end]))
    }
}
