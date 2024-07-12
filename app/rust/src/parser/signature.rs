use minicbor::{decode::Error, Decode, Decoder};

use crate::constants::BLS_SIGNATURE_SIZE;

use super::raw_value::RawValue;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature<'a>(&'a [u8; BLS_SIGNATURE_SIZE]);

impl<'a> Signature<'a> {
    pub fn bls_signature(&self) -> &[u8; BLS_SIGNATURE_SIZE] {
        self.0
    }
}

impl<'a> TryFrom<RawValue<'a>> for Signature<'a> {
    type Error = Error;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut d = Decoder::new(value.bytes());
        Self::decode(&mut d, &mut ())
    }
}

impl<'b, C> Decode<'b, C> for Signature<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        // Expect Bytes and ensure we have at leaste 48-bytes
        #[cfg(test)]
        std::println!("raw_signature {:?}", d.input());
        let b = d.bytes()?;
        if b.len() != BLS_SIGNATURE_SIZE {
            return Err(Error::message("Invalid BLS signature length"));
        }

        Ok(Signature(arrayref::array_ref!(b, 0, BLS_SIGNATURE_SIZE)))
    }
}
