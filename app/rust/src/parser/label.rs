use minicbor::{decode::Error, Decode, Decoder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label<'a> {
    Blob(&'a [u8]),
    String(&'a str),
}

impl<'a> Label<'a> {
    fn as_bytes(&self) -> &'a [u8] {
        match self {
            Label::Blob(b) => b,
            Label::String(s) => s.as_bytes(),
        }
    }
}

impl<'b, C> Decode<'b, C> for Label<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        match d.datatype()? {
            minicbor::data::Type::Bytes => {
                let bytes = d.bytes()?;
                match core::str::from_utf8(bytes) {
                    Ok(s) => Ok(Label::String(s)),
                    Err(_) => Ok(Label::Blob(bytes)),
                }
            }
            minicbor::data::Type::String => Ok(Label::String(d.str()?)),
            _ => Err(Error::message("Expected bytes or string for Label")),
        }
    }
}
