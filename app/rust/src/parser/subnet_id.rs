use minicbor::{data::Type, decode::Error, Decode, Decoder};

use super::raw_value::RawValue;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SubnetId<'a>(RawValue<'a>);

impl<'a> SubnetId<'a> {
    pub fn id(&self) -> &'a [u8] {
        let mut d = Decoder::new(self.0.bytes());
        // safe to unwrap, this was check at parsing stage
        d.bytes().unwrap()
    }
}

impl<'a> TryFrom<RawValue<'a>> for SubnetId<'a> {
    type Error = Error;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut d = Decoder::new(value.bytes());
        Self::decode(&mut d, &mut ())
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
