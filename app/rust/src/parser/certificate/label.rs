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

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum Label<'a> {
    Blob(&'a [u8]),
    String(&'a str),
}

impl<'a> Label<'a> {
    // TODO: Check if docs tell something about
    // max label length
    pub const MAX_LEN: usize = 32;
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            Label::Blob(b) => b,
            Label::String(s) => s.as_bytes(),
        }
    }
}

impl<'a> From<&'a str> for Label<'a> {
    fn from(s: &'a str) -> Self {
        Label::String(s)
    }
}

impl<'a> From<&'a [u8]> for Label<'a> {
    fn from(b: &'a [u8]) -> Self {
        Label::Blob(b)
    }
}

impl<'b, C> Decode<'b, C> for Label<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        match d.datatype()? {
            minicbor::data::Type::Bytes => {
                let bytes = d.bytes()?;
                match core::str::from_utf8(bytes) {
                    Ok(s) => Ok(Label::String(s)),
                    Err(_) => Ok(Label::Blob(bytes)),
                }
            }
            minicbor::data::Type::String => Ok(Label::String(d.str()?)),
            _ => Err(Error::message("Expected bytes or string for Label")),
        }
    }
}
