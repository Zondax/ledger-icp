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
use minicbor::{data::Type, Decoder};

use crate::{error::ParserError, FromBytes};

use super::raw_value::RawValue;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct SubnetId<'a>(RawValue<'a>);

impl<'a> SubnetId<'a> {
    pub fn id(&self) -> &'a [u8] {
        let mut d = Decoder::new(self.0.bytes());
        // safe to unwrap, this was check at parsing stage
        d.bytes().unwrap()
    }
}
impl<'a> TryFrom<&RawValue<'a>> for SubnetId<'a> {
    type Error = ParserError;

    fn try_from(value: &RawValue<'a>) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl<'a> TryFrom<RawValue<'a>> for SubnetId<'a> {
    type Error = ParserError;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut raw_value = MaybeUninit::uninit();
        _ = SubnetId::from_bytes_into(value.bytes(), &mut raw_value)?;
        Ok(unsafe { raw_value.assume_init() })
    }
}

impl<'a> FromBytes<'a> for SubnetId<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], crate::error::ParserError> {
        let out = out.as_mut_ptr();

        let d = Decoder::new(input);

        // Expect Bytes
        if d.datatype()? != Type::Bytes {
            return Err(ParserError::UnexpectedType);
        }

        let data = &input[d.position()..];

        let raw_value: &mut MaybeUninit<RawValue<'a>> =
            unsafe { &mut *addr_of_mut!((*out).0).cast() };

        let rem = RawValue::from_bytes_into(data, raw_value)?;

        Ok(rem)
    }
}
