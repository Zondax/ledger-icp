use minicbor::{decode::Error, Decode, Decoder};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RawValue<'a>(&'a [u8]);

impl<'a> RawValue<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        RawValue::decode(&mut d, &mut ())
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'b, C> Decode<'b, C> for RawValue<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, Error> {
        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(RawValue(&d.input()[start..end]))
    }
}

pub struct RawValueError;
