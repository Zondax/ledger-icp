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

use crate::constants::BLS_PUBLIC_KEY_SIZE;

use super::raw_value::RawValue;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct PublicKey<'a>(&'a [u8; BLS_PUBLIC_KEY_SIZE]);

impl<'a> PublicKey<'a> {
    pub fn as_bytes(&self) -> &'a [u8; BLS_PUBLIC_KEY_SIZE] {
        self.0
    }
}

impl<'b, C> Decode<'b, C> for PublicKey<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        // Decode CBOR wrapper
        let array_len = d.array()?;
        if array_len != Some(2) {
            return Err(Error::message("Expected array of length 2"));
        }

        // Read algorithm identifier
        d.u8()?;

        // Read key data
        let der_data = d.bytes()?;

        // Parse SubjectPublicKeyInfo
        let mut index = 0;

        // SEQUENCE tag
        if der_data[index] != 0x30 {
            return Err(Error::message("Invalid SubjectPublicKeyInfo"));
        }
        index += 1;

        // Skip length
        let mut len = der_data[index] as usize;
        index += 1;
        if len > 0x80 {
            let len_bytes = len - 0x80;
            len = 0;
            for _ in 0..len_bytes {
                len = (len << 8) | (der_data[index] as usize);
                index += 1;
            }
        }

        // AlgorithmIdentifier
        if der_data[index] != 0x30 {
            return Err(Error::message("Invalid AlgorithmIdentifier"));
        }
        index += 1;

        // Skip AlgorithmIdentifier contents
        let alg_len = der_data[index] as usize;
        index += 1 + alg_len;

        // BIT STRING tag for subjectPublicKey
        if der_data[index] != 0x03 {
            return Err(Error::message("Invalid subjectPublicKey"));
        }
        index += 1;

        // BIT STRING length
        index += 1;

        // Skip initial octet of BIT STRING (should be 00)
        index += 1;

        // The rest is the actual public key
        let key_data = &der_data[index..];
        if key_data.len() != BLS_PUBLIC_KEY_SIZE {
            return Err(Error::message("Insufficient key data"));
        }

        // Use array_ref! to get a reference to a fixed-size array
        let pubkey = arrayref::array_ref!(key_data, 0, BLS_PUBLIC_KEY_SIZE);
        Ok(Self(pubkey))
    }
}

impl<'a> TryFrom<RawValue<'a>> for PublicKey<'a> {
    type Error = Error;
    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut d = Decoder::new(value.bytes());
        Self::decode(&mut d, &mut ())
    }
}

impl<'a> TryFrom<&'a [u8]> for PublicKey<'a> {
    type Error = Error;
    fn try_from(der_data: &'a [u8]) -> Result<Self, Self::Error> {
        // Parse SubjectPublicKeyInfo
        let mut index = 0;

        // SEQUENCE tag
        if der_data[index] != 0x30 {
            return Err(Error::message("Invalid SubjectPublicKeyInfo"));
        }
        index += 1;

        // Skip length
        let mut len = der_data[index] as usize;
        index += 1;
        if len > 0x80 {
            let len_bytes = len - 0x80;
            len = 0;
            for _ in 0..len_bytes {
                len = (len << 8) | (der_data[index] as usize);
                index += 1;
            }
        }

        // AlgorithmIdentifier
        if der_data[index] != 0x30 {
            return Err(Error::message("Invalid AlgorithmIdentifier"));
        }
        index += 1;

        // Skip AlgorithmIdentifier contents
        let alg_len = der_data[index] as usize;
        index += 1 + alg_len;

        // BIT STRING tag for subjectPublicKey
        if der_data[index] != 0x03 {
            return Err(Error::message("Invalid subjectPublicKey"));
        }
        index += 1;

        // BIT STRING length
        index += 1;

        // Skip initial octet of BIT STRING (should be 00)
        index += 1;

        // The rest is the actual public key
        let key_data = &der_data[index..];
        if key_data.len() != BLS_PUBLIC_KEY_SIZE {
            return Err(Error::message("Insufficient key data"));
        }

        // Use array_ref! to get a reference to a fixed-size array
        let pubkey = arrayref::array_ref!(key_data, 0, BLS_PUBLIC_KEY_SIZE);
        Ok(Self(pubkey))
    }
}
