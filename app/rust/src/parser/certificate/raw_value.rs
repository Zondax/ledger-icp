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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RawValue<'a>(&'a [u8]);

impl<'a> RawValue<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        RawValue::decode(&mut d, &mut ())
    }

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

impl<'b, C> Decode<'b, C> for RawValue<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, Error> {
        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(RawValue(&d.input()[start..end]))
    }
}

pub struct RawValueError;
