use minicbor::{decode::Error, Decode, Decoder};

use super::raw_value::RawValue;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delegation<'a> {
    subnet_id: RawValue<'a>,
    certificate: RawValue<'a>,
}

impl<'b, C> Decode<'b, C> for Delegation<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        // Expect a map with 2 entries
        let len = d.map()?.ok_or(Error::message("Expected a map"))?;
        if len != 2 {
            return Err(Error::message("Expected a map with 2 entries"));
        }

        let mut subnet_id = None;
        let mut certificate = None;

        for _ in 0..2 {
            match d.str()? {
                "subnet_id" => subnet_id = Some(RawValue::decode(d, ctx)?),
                "certificate" => certificate = Some(RawValue::decode(d, ctx)?),
                _ => return Err(Error::message("Unexpected key in delegation")),
            }
        }

        Ok(Delegation {
            subnet_id: subnet_id.ok_or(Error::message("Missing subnet_id"))?,
            certificate: certificate.ok_or(Error::message("Missing certificate"))?,
        })
    }
}
