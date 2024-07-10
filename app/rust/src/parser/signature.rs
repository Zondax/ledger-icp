use minicbor::{data::Type, decode::Error, Decode, Decoder};

use super::raw_value::RawValue;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature<'a>(RawValue<'a>);

impl<'a> Signature<'a> {
    pub const BLS_SIGNATURE_SIZE: usize = 48;

    pub fn bls_signature(&self) -> Result<&[u8], Error> {
        let mut d = Decoder::new(self.0.bytes());
        let b = d.bytes()?;
        if b.len() != Self::BLS_SIGNATURE_SIZE {
            return Err(Error::message("Invalid BLS signature length"));
        }
        Ok(b)
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
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        // Expect Bytes
        if d.datatype()? != Type::Bytes {
            return Err(Error::type_mismatch(Type::Bytes));
        }

        Ok(Signature(RawValue::decode(d, ctx)?))
    }
}
