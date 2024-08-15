use core::mem::MaybeUninit;

use minicbor::{data::Type, decode::Error, Decode, Decoder};

use crate::{
    constants::CALL_REQUEST_TAG,
    error::ParserError,
    utils::{compress_leb128, hash_blob, hash_str},
    FromBytes,
};

// {"content": {"arg": h'4449444C00017104746F6269', "canister_id": h'00000000006000FD0101',
// "ingress_expiry": 1712667140606000000, "method_name": "greet", "request_type": "query", "sender": h'04'}}
#[derive(PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct CallRequest<'a> {
    pub arg: &'a [u8],
    pub sender: &'a [u8],
    pub canister_id: &'a [u8],
    pub method_name: &'a str,
    pub request_type: &'a str,
    pub ingress_expiry: u64,
    pub nonce: Option<&'a [u8]>,
}

impl<'a> CallRequest<'a> {
    pub fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParserError> {
        let mut decoder = Decoder::new(data);
        let this =
            Decode::decode(&mut decoder, &mut ()).map_err(|_| ParserError::InvalidCallRequest)?;

        let consumed = decoder.position();

        Ok((&data[consumed..], this))
    }

    pub fn arg(&self) -> &[u8] {
        self.arg
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

    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce
    }

    pub fn digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();

        // Helper function to hash a field
        let mut hash_field = |name: &str, value: &[u8]| {
            hasher.update(hash_str(name));
            hasher.update(hash_blob(value));
        };

        // Hash fields in the same order as the C function
        hash_field("sender", self.sender);
        hash_field("canister_id", self.canister_id);

        // Hash ingress_expiry (u64)
        let mut buf = [0u8; 10];
        hash_field(
            "ingress_expiry",
            compress_leb128(self.ingress_expiry, &mut buf),
        );

        hash_field("method_name", self.method_name.as_bytes());
        hash_field("request_type", self.request_type.as_bytes());

        // Hash nonce if present
        if let Some(nonce) = self.nonce {
            hash_field("nonce", nonce);
        }

        // Hash arg last
        hash_field("arg", self.arg);

        // Finalize and return the hash
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

impl<'a> FromBytes<'a> for CallRequest<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'a [u8], crate::error::ParserError> {
        let (rem, cert) = Self::parse(input)?;

        out.write(cert);

        Ok(rem)
    }
}

impl<'b, C> Decode<'b, C> for CallRequest<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        // check tag, which is the same value as certificate, why?
        if let Ok(tag) = d.tag() {
            if tag.as_u64() != CALL_REQUEST_TAG {
                return Err(Error::message("Expected tag"));
            }
        }

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
        if content_len != 6 && content_len != 7 {
            return Err(Error::message("Expected a content map with 6/7 entries"));
        }

        let mut arg = None;
        let mut sender = None;
        let mut nonce = None;
        let mut canister_id = None;
        let mut method_name = None;
        let mut request_type = None;
        let mut ingress_expiry = None;

        for _ in 0..content_len as usize {
            let key = d.str()?;
            match key {
                "arg" => arg = Some(d.bytes()?),
                "sender" => sender = Some(d.bytes()?),
                "canister_id" => canister_id = Some(d.bytes()?),
                "method_name" => method_name = Some(d.str()?),
                "request_type" => request_type = Some(d.str()?),
                "ingress_expiry" => ingress_expiry = Some(d.u64()?),
                "nonce" => nonce = Some(d.bytes()?),
                _ => return Err(Error::message("Unexpected key in content map")),
            }
        }

        Ok(CallRequest {
            arg: arg.ok_or(Error::message("Missing arg"))?,
            sender: sender.ok_or(Error::message("Missing sender"))?,
            nonce,
            canister_id: canister_id.ok_or(Error::message("Missing canister_id"))?,
            method_name: method_name.ok_or(Error::message("Missing method_name"))?,
            request_type: request_type.ok_or(Error::message("Missing request_type"))?,
            ingress_expiry: ingress_expiry.ok_or(Error::message("Missing ingress_expiry"))?,
        })
    }
}

#[cfg(test)]
mod call_request_test {
    use minicbor::Decoder;

    use super::*;

    // This is CBOR data
    const REQUEST: &str = "d9d9f7a167636f6e74656e74a6636172674c4449444c00017104746f62696b63616e69737465725f69644a00000000006000fd01016e696e67726573735f6578706972791bf710af546aca20006b6d6574686f645f6e616d656567726565746c726571756573745f747970656571756572796673656e6465724104";

    #[test]
    fn call_parse() {
        let data = hex::decode(REQUEST).unwrap();
        let mut decoder = Decoder::new(&data);
        let call_request: CallRequest = Decode::decode(&mut decoder, &mut ()).unwrap();
        std::println!("CallRequest: {:?}", call_request);

        assert_eq!(
            call_request.arg,
            &[68, 73, 68, 76, 0, 1, 113, 4, 116, 111, 98, 105]
        );
        assert_eq!(call_request.sender, &[4]);
        assert_eq!(call_request.canister_id, &[0, 0, 0, 0, 0, 96, 0, 253, 1, 1]);
        assert_eq!(call_request.method_name, "greet");
        assert_eq!(call_request.request_type, "query");
        assert_eq!(call_request.ingress_expiry, 17802922104099315712);
    }
}
