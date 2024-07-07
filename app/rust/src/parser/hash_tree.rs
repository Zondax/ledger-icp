use minicbor::{decode::Error, Decode, Decoder};

use super::{label::Label, raw_value::RawValue};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashTree<'a> {
    Empty,
    Fork(RawValue<'a>, RawValue<'a>),
    Labeled(Label<'a>, RawValue<'a>),
    Leaf(RawValue<'a>),
    Pruned(RawValue<'a>),
}

impl<'b, C> Decode<'b, C> for HashTree<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let tag = u8::decode(d, ctx)?;
        match tag {
            0 => Ok(HashTree::Empty),
            1 => Ok(HashTree::Fork(
                RawValue::decode(d, ctx)?,
                RawValue::decode(d, ctx)?,
            )),
            2 => Ok(HashTree::Labeled(
                Label::decode(d, ctx)?,
                RawValue::decode(d, ctx)?,
            )),
            3 => Ok(HashTree::Leaf(RawValue::decode(d, ctx)?)),
            4 => Ok(HashTree::Pruned(RawValue::decode(d, ctx)?)),
            _ => Err(Error::message("Invalid HashTree tag")),
        }
    }
}
