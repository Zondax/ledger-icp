use minicbor::{decode::Error, Decode, Decoder};

use super::raw_value::RawValue;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Label<'a> {
    Blob(RawValue<'a>),
    String(RawValue<'a>),
}

impl<'b, C> Decode<'b, C> for Label<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let tag = u8::decode(d, ctx)?;
        match tag {
            0 => Ok(Label::Blob(RawValue::decode(d, ctx)?)),
            1 => Ok(Label::String(RawValue::decode(d, ctx)?)),
            _ => Err(Error::message("Invalid Label tag")),
        }
    }
}
