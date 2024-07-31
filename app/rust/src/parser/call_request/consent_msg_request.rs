use core::mem::MaybeUninit;
use minicbor::{data::Type, decode::Error, Decode, Decoder};

use crate::{constants::CONSENT_MSG_REQUEST_TAG, error::ParserError, FromBytes};

// {"content": {"arg": h'4449444C076D7B6C01D880C6D007716C02CBAEB581017AB183E7F1077A6B028BEABFC2067F8EF1C1EE0D026E036C02EFCEE7800401C4FBF2DB05046C03D6FCA70200E1EDEB4A7184F7FEE80A0501060C4449444C00017104746F626905677265657402656E01011E000300',
// "canister_id": h'00000000006000FD0101', "ingress_expiry": 1712666698482000000,
// "method_name": "icrc21_canister_call_consent_message", "nonce": h'A3788C1805553FB69B20F08E87E23B13',
// "request_type": "call", "sender": h'04'}}
#[derive(Debug, PartialEq)]
pub struct ConsentMsgRequest<'a> {
    pub arg: &'a [u8],
    pub nonce: &'a [u8],
    pub sender: &'a [u8],
    pub canister_id: &'a [u8],
    pub method_name: &'a str,
    pub request_type: &'a str,
    pub ingress_expiry: u64,
}

impl<'a> ConsentMsgRequest<'a> {
    pub fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParserError> {
        let mut decoder = Decoder::new(data);
        let this = Decode::decode(&mut decoder, &mut ())
            .map_err(|_| ParserError::InvalidConsentMsgRequest)?;

        let consumed = decoder.position();

        Ok((&data[consumed..], this))
    }

    // Getter methods (unchanged)
    pub fn arg(&self) -> &[u8] {
        self.arg
    }
    pub fn nonce(&self) -> &[u8] {
        self.nonce
    }
    pub fn sender(&self) -> &[u8] {
        self.sender
    }
    pub fn canister_id(&self) -> &[u8] {
        self.canister_id
    }
    pub fn method_name(&self) -> &str {
        self.method_name
    }
    pub fn request_type(&self) -> &str {
        self.request_type
    }
    pub fn ingress_expiry(&self) -> u64 {
        self.ingress_expiry
    }
}

impl<'a> FromBytes<'a> for ConsentMsgRequest<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let (rem, request) = Self::parse(input)?;
        out.write(request);
        Ok(rem)
    }
}

impl<'b, C> Decode<'b, C> for ConsentMsgRequest<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        // Check tag
        if let Ok(tag) = d.tag() {
            if tag.as_u64() != CONSENT_MSG_REQUEST_TAG {
                return Err(Error::message("Expected tag"));
            }
        }

        // Decode outer map
        let len = d.map()?.ok_or(Error::type_mismatch(Type::Map))?;
        if len != 1 {
            return Err(Error::message("Expected a map with 1 entry"));
        }

        let key = d.str()?;
        if key != "content" {
            return Err(Error::message("Expected 'content' key"));
        }

        // Decode content map
        let content_len = d.map()?.ok_or(Error::message("Expected a content map"))?;
        if content_len != 7 {
            return Err(Error::message("Expected a content map with 7 entries"));
        }

        let mut arg = None;
        let mut nonce = None;
        let mut sender = None;
        let mut canister_id = None;
        let mut method_name = None;
        let mut request_type = None;
        let mut ingress_expiry = None;

        for _ in 0..7 {
            let key = d.str()?;
            match key {
                "arg" => arg = Some(d.bytes()?),
                "nonce" => nonce = Some(d.bytes()?),
                "sender" => sender = Some(d.bytes()?),
                "canister_id" => canister_id = Some(d.bytes()?),
                "method_name" => method_name = Some(d.str()?),
                "request_type" => request_type = Some(d.str()?),
                "ingress_expiry" => ingress_expiry = Some(d.u64()?),
                _ => return Err(Error::message("Unexpected key in content map")),
            }
        }

        Ok(ConsentMsgRequest {
            arg: arg.ok_or(Error::message("Missing arg"))?,
            nonce: nonce.ok_or(Error::message("Missing nonce"))?,
            sender: sender.ok_or(Error::message("Missing sender"))?,
            canister_id: canister_id.ok_or(Error::message("Missing canister_id"))?,
            method_name: method_name.ok_or(Error::message("Missing method_name"))?,
            request_type: request_type.ok_or(Error::message("Missing request_type"))?,
            ingress_expiry: ingress_expiry.ok_or(Error::message("Missing ingress_expiry"))?,
        })
    }
}

#[cfg(test)]
mod call_request_test {
    use super::*;

    const REQUEST: &str = "d9d9f7a167636f6e74656e74a763617267586b4449444c076d7b6c01d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d026e036c02efcee7800401c4fbf2db05046c03d6fca70200e1edeb4a7184f7fee80a0501060c4449444c00017104746f626905677265657402656e01011e0003006b63616e69737465725f69644a00000000006000fd01016e696e67726573735f6578706972791bf0edf1e9943528006b6d6574686f645f6e616d6578246963726332315f63616e69737465725f63616c6c5f636f6e73656e745f6d657373616765656e6f6e636550a3788c1805553fb69b20f08e87e23b136c726571756573745f747970656463616c6c6673656e6465724104";

    #[test]
    fn msg_request() {
        let data = hex::decode(REQUEST).unwrap();
        let (_, msg_req) = ConsentMsgRequest::parse(&data).unwrap();

        assert_eq!(msg_req.arg.len(), 107); // The arg is quite long, so we'll just check its length
        assert_eq!(
            msg_req.nonce,
            &[163, 120, 140, 24, 5, 85, 63, 182, 155, 32, 240, 142, 135, 226, 59, 19]
        );
        assert_eq!(msg_req.sender, &[4]);
        assert_eq!(msg_req.canister_id, &[0, 0, 0, 0, 0, 96, 0, 253, 1, 1]);
        assert_eq!(msg_req.method_name, "icrc21_canister_call_consent_message");
        assert_eq!(msg_req.request_type, "call");
        assert_eq!(msg_req.ingress_expiry, 17360798124099315712);
    }
}
