use minicbor::{data::Type, decode::Error, Decode, Decoder};

use super::raw_value::RawValue;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKey<'a>(RawValue<'a>);

impl<'a> PublicKey<'a> {
    pub const BLS_PUBLIC_KEY_SIZE: usize = 96;

    pub fn bls_pubkey(&self) -> Result<&'a [u8], Error> {
        let raw_value = self.0.bytes();
        let mut d = Decoder::new(raw_value);

        // Decode CBOR wrapper
        let array_len = d.array().unwrap();
        if array_len != Some(2) {
            return Err(Error::message("Expected array of length 2"));
        }

        // Read algorithm identifier
        d.u8()?;

        // read key data
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

        if key_data.len() >= Self::BLS_PUBLIC_KEY_SIZE {
            Ok(&key_data[..Self::BLS_PUBLIC_KEY_SIZE])
        } else {
            Err(Error::message("Insufficient key data"))
        }
    }
}

impl<'a> TryFrom<RawValue<'a>> for PublicKey<'a> {
    type Error = Error;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut d = Decoder::new(value.bytes());
        Self::decode(&mut d, &mut ())
    }
}

impl<'b, C> Decode<'b, C> for PublicKey<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        // Expect Bytes
        if d.datatype()? != Type::Array {
            return Err(Error::type_mismatch(Type::Array));
        }

        Ok(PublicKey(RawValue::decode(d, ctx)?))
    }
}
