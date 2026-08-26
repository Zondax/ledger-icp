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

        let key = Self::try_from(der_data)?;

        Ok(key)
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
        // This walks DER taken from a delegation that has not been verified yet,
        // so every read is bounds-checked and every advance is checked for
        // overflow. Indexing directly would panic on truncated or hostile input,
        // and with panic=abort plus a `loop {}` handler that hangs the device.
        #[inline(always)]
        fn byte_at(data: &[u8], index: usize) -> Result<u8, Error> {
            data.get(index)
                .copied()
                .ok_or_else(|| Error::message("Truncated SubjectPublicKeyInfo"))
        }

        #[inline(always)]
        fn advance(index: usize, by: usize) -> Result<usize, Error> {
            index
                .checked_add(by)
                .ok_or_else(|| Error::message("Malformed SubjectPublicKeyInfo length"))
        }

        // Parse SubjectPublicKeyInfo
        let mut index = 0;

        // SEQUENCE tag
        if byte_at(der_data, index)? != 0x30 {
            return Err(Error::message("Invalid SubjectPublicKeyInfo"));
        }
        index = advance(index, 1)?;

        // Skip length
        let mut len = byte_at(der_data, index)? as usize;
        index = advance(index, 1)?;
        if len > 0x80 {
            let len_bytes = len - 0x80;
            len = 0;
            for _ in 0..len_bytes {
                len = (len << 8) | (byte_at(der_data, index)? as usize);
                index = advance(index, 1)?;
            }
        }
        let _ = len;

        // AlgorithmIdentifier
        if byte_at(der_data, index)? != 0x30 {
            return Err(Error::message("Invalid AlgorithmIdentifier"));
        }
        index = advance(index, 1)?;

        // Skip AlgorithmIdentifier contents
        let alg_len = byte_at(der_data, index)? as usize;
        index = advance(index, advance(1, alg_len)?)?;

        // BIT STRING tag for subjectPublicKey
        if byte_at(der_data, index)? != 0x03 {
            return Err(Error::message("Invalid subjectPublicKey"));
        }
        index = advance(index, 1)?;

        // BIT STRING length
        index = advance(index, 1)?;

        // Skip initial octet of BIT STRING (should be 00)
        index = advance(index, 1)?;

        // The rest is the actual public key
        let key_data = der_data
            .get(index..)
            .ok_or_else(|| Error::message("Truncated subjectPublicKey"))?;
        if key_data.len() != BLS_PUBLIC_KEY_SIZE {
            return Err(Error::message("Insufficient key data"));
        }

        // Use array_ref! to get a reference to a fixed-size array
        let pubkey = arrayref::array_ref!(key_data, 0, BLS_PUBLIC_KEY_SIZE);
        Ok(Self(pubkey))
    }
}

#[cfg(test)]
mod test_pubkey {
    pub const CANISTER_ROOT_KEY: &str = "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae";

    use super::*;

    // The real root key to use for certificate verification
    // taken from:
    // https://github.com/dfinity/ic-canister-sig-creation/blob/bb1bf7c4114190b1b754a85847d1a7040358184d/src/lib.rs#L12C1-L12C576
    pub const IC_ROOT_PK_DER: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

    #[test]
    fn hostile_der_is_rejected_without_panicking() {
        // Each of these used to index past the end of the slice. On device a
        // panic aborts into a `loop {}` handler, so it hangs until reconnect --
        // and this DER comes from a delegation that has not been verified yet.
        let cases: [&[u8]; 7] = [
            &[],                                   // empty
            &[0x30],                               // truncated after SEQUENCE
            &[0x30, 0x82],                         // long-form length runs off the end
            &[0x30, 0x05],                         // no AlgorithmIdentifier
            &[0x30, 0x10, 0x30],                   // truncated algorithm length
            &[0x30, 0x10, 0x30, 0xFF, 0x00, 0x00], // alg_len skips past the end
            &[0x30, 0x10, 0x30, 0x01, 0x00, 0x04], // wrong BIT STRING tag
        ];

        for case in cases {
            assert!(
                PublicKey::try_from(case).is_err(),
                "must be rejected, not panic: {case:02x?}"
            );
        }
    }

    #[test]
    fn der_convert() {
        let key = PublicKey::try_from(IC_ROOT_PK_DER.as_ref()).unwrap();
        assert_eq!(key.as_bytes().len(), BLS_PUBLIC_KEY_SIZE);
        assert_eq!(hex::encode(key.as_bytes()), CANISTER_ROOT_KEY);
    }
}
