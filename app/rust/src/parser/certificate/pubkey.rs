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
    // Walks SubjectPublicKeyInfo far enough to reach subjectPublicKey. The
    // input is a leaf value taken from a certificate tree, so its length and
    // every length byte inside it are attacker-chosen: each read is bounds
    // checked and each advance is checked for overflow, rather than indexing
    // and hoping the buffer is long enough.
    fn try_from(der_data: &'a [u8]) -> Result<Self, Self::Error> {
        fn byte_at(data: &[u8], index: usize) -> Result<u8, Error> {
            data.get(index)
                .copied()
                .ok_or_else(|| Error::message("Truncated SubjectPublicKeyInfo"))
        }

        // Reads a DER length, returning it along with the index just past it.
        fn read_len(data: &[u8], mut index: usize) -> Result<(usize, usize), Error> {
            let first = byte_at(data, index)?;
            index += 1;

            if first < 0x80 {
                return Ok((first as usize, index));
            }
            if first == 0x80 || first == 0xFF {
                return Err(Error::message("Invalid DER length"));
            }

            let count = (first & 0x7F) as usize;
            // Anything wider than usize cannot describe a slice of this input.
            if count > core::mem::size_of::<usize>() {
                return Err(Error::message("DER length too large"));
            }

            let mut len = 0usize;
            for _ in 0..count {
                len = (len << 8) | byte_at(data, index)? as usize;
                index += 1;
            }
            Ok((len, index))
        }

        let mut index = 0;

        // SEQUENCE tag
        if byte_at(der_data, index)? != 0x30 {
            return Err(Error::message("Invalid SubjectPublicKeyInfo"));
        }
        index += 1;
        let (_, next) = read_len(der_data, index)?;
        index = next;

        // AlgorithmIdentifier
        if byte_at(der_data, index)? != 0x30 {
            return Err(Error::message("Invalid AlgorithmIdentifier"));
        }
        index += 1;
        let (alg_len, next) = read_len(der_data, index)?;
        index = next
            .checked_add(alg_len)
            .ok_or_else(|| Error::message("Invalid AlgorithmIdentifier"))?;

        // BIT STRING tag for subjectPublicKey
        if byte_at(der_data, index)? != 0x03 {
            return Err(Error::message("Invalid subjectPublicKey"));
        }
        index += 1;
        let (bit_string_len, next) = read_len(der_data, index)?;
        index = next;

        // Skip the initial octet of the BIT STRING, which counts the unused
        // trailing bits and must be zero for a whole number of octets.
        if byte_at(der_data, index)? != 0x00 {
            return Err(Error::message("Invalid subjectPublicKey padding"));
        }
        index += 1;

        // The declared length covers the unused-bits octet as well.
        if bit_string_len != BLS_PUBLIC_KEY_SIZE + 1 {
            return Err(Error::message("Insufficient key data"));
        }

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
    fn der_convert() {
        let key = PublicKey::try_from(IC_ROOT_PK_DER.as_ref()).unwrap();
        assert_eq!(key.as_bytes().len(), BLS_PUBLIC_KEY_SIZE);
        assert_eq!(hex::encode(key.as_bytes()), CANISTER_ROOT_KEY);
    }

    // The DER here is a leaf value pulled out of a certificate tree, so its
    // length and its internal length bytes are whatever the host sent. Every
    // one of these used to index straight past the end of the slice.
    #[test]
    fn malformed_der_is_an_error_not_a_panic() {
        assert!(PublicKey::try_from(&[][..]).is_err());
        assert!(PublicKey::try_from(&[0x30][..]).is_err());
        assert!(PublicKey::try_from(&[0x30, 0x81][..]).is_err());

        // Truncated at every prefix of a key that otherwise parses.
        for cut in 0..IC_ROOT_PK_DER.len() {
            assert!(
                PublicKey::try_from(&IC_ROOT_PK_DER[..cut]).is_err(),
                "prefix of length {} was accepted",
                cut
            );
        }

        // AlgorithmIdentifier claiming more content than the buffer holds, so
        // the skip past it runs off the end.
        let mut oversized_alg = IC_ROOT_PK_DER.to_vec();
        oversized_alg[4] = 0x7F;
        assert!(PublicKey::try_from(oversized_alg.as_slice()).is_err());

        // A multi-byte length whose byte count alone exceeds the input.
        assert!(PublicKey::try_from(&[0x30, 0x88, 0xFF, 0xFF][..]).is_err());

        // Reserved DER length forms.
        assert!(PublicKey::try_from(&[0x30, 0x80, 0x30, 0x00][..]).is_err());
        assert!(PublicKey::try_from(&[0x30, 0xFF, 0x30, 0x00][..]).is_err());

        // Right shape, wrong key size: one byte short of BLS_PUBLIC_KEY_SIZE.
        let mut short_key = IC_ROOT_PK_DER.to_vec();
        short_key.pop();
        assert!(PublicKey::try_from(short_key.as_slice()).is_err());
    }
}
