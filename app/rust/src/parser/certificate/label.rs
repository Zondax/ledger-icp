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

#[derive(Clone, Copy, Eq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum Label<'a> {
    Blob(&'a [u8]),
    String(&'a str),
}

// Labels are byte strings. Decoding hands back any label that happens to be
// valid UTF-8 as a String, so comparing variants made it differ from the same
// bytes looked up as a Blob: a request id or subnet id made only of ASCII bytes
// could never be found in the tree.
impl PartialEq for Label<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<'a> Label<'a> {
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
        // MAX_LEN is what the hashing buffer in HashTree::reconstruct is sized
        // for. Nothing in a well-formed certificate exceeds it - the longest
        // labels are 32-byte request ids - so reject the rest here instead of
        // letting an oversized one reach a fixed-size copy.
        let label = match d.datatype()? {
            minicbor::data::Type::Bytes => {
                let bytes = d.bytes()?;
                match core::str::from_utf8(bytes) {
                    Ok(s) => Label::String(s),
                    Err(_) => Label::Blob(bytes),
                }
            }
            minicbor::data::Type::String => Label::String(d.str()?),
            _ => return Err(Error::message("Expected bytes or string for Label")),
        };

        if label.as_bytes().len() > Self::MAX_LEN {
            return Err(Error::message("Label exceeds maximum length"));
        }

        Ok(label)
    }
}

#[cfg(test)]
mod test_label {
    use super::Label;

    #[test]
    fn labels_compare_as_bytes() {
        let blob: &[u8] = b"request_status";
        assert_eq!(Label::from("request_status"), Label::from(blob));

        // An all-zero subnet id is valid UTF-8, so it decodes as a String.
        let zeros = [0u8; 29];
        let decoded = Label::String(core::str::from_utf8(&zeros).unwrap());
        assert_eq!(decoded, Label::from(&zeros[..]));

        assert_ne!(Label::from("status"), Label::from(&b"statuz"[..]));
        assert_ne!(Label::from("status"), Label::from(&b"status\0"[..]));
    }
}
