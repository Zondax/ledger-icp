use core::ptr::addr_of_mut;

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
use minicbor::{data::Type, decode::Error, Decode, Decoder};

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
    type Error = Error;

    fn try_from(value: &RawValue<'a>) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl<'a> TryFrom<RawValue<'a>> for SubnetId<'a> {
    type Error = Error;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut d = Decoder::new(value.bytes());
        Self::decode(&mut d, &mut ())
    }
}

impl<'a> FromBytes<'a> for SubnetId<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], crate::error::ParserError> {
        let mut d = Decoder::new(input);
        // Expect Bytes
        if d.datatype()? != Type::Bytes {
            return Err(ParserError::UnexpectedType);
        }

        let raw_value = RawValue::decode(&mut d, &mut ())?;

        let out = out.as_mut_ptr();

        unsafe {
            addr_of_mut!((*out).0).write(raw_value);
        }

        Ok(&input[d.position()..])
    }
}

impl<'b, C> Decode<'b, C> for SubnetId<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        // Expect Bytes
        if d.datatype()? != Type::Bytes {
            return Err(Error::type_mismatch(Type::Bytes));
        }

        Ok(SubnetId(RawValue::decode(d, ctx)?))
    }
}
