use minicbor::{decode::Error, Decode, Decoder};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RawValue<'a>(&'a [u8]);

impl<'b, C> Decode<'b, C> for RawValue<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, Error> {
        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(RawValue(&d.input()[start..end]))
    }
}

pub struct RawValueError;
