use minicbor::{data::Type, decode::Error, Decode, Decoder};

use super::raw_value::RawValue;

const DELEGATION_MAP_ENTRIES: u64 = 2;

const SUBNET_ID: &str = "subnet_id";
const CERTIFICATE: &str = "certificate";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delegation<'a> {
    subnet_id: RawValue<'a>,
    certificate: RawValue<'a>,
}

impl<'a> Delegation<'a> {
    pub fn certificate(&self) -> &RawValue<'a> {
        &self.certificate
    }
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
            let key = d.str()?;

            match key {
                "subnet_id" => {
                    subnet_id = Some(RawValue::decode(d, ctx)?);
                }
                "certificate" => {
                    if d.datatype()? == Type::Bytes {
                        let bytes = d.bytes()?;
                        let mut dec = Decoder::new(bytes);
                        let raw = RawValue::decode(&mut dec, ctx)?;
                        certificate = Some(raw);
                    } else {
                        return Err(Error::message("Expected byte string for certificate"));
                    }
                }
                _ => return Err(Error::message("Unexpected key in delegation")),
            }
        }

        Ok(Delegation {
            subnet_id: subnet_id.ok_or(Error::message("Missing subnet_id"))?,
            certificate: certificate.ok_or(Error::message("Missing certificate"))?,
        })
    }
}
