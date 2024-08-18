use core::{mem::MaybeUninit, ptr::addr_of_mut};

use minicbor::Decoder;

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

    // Compute the hash of the call request
    // this is going to be signed
    // order of the fields is important
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
        crate::zlog("CallRequest::from_bytes_into\x00");
        let out = out.as_mut_ptr();

        let mut d = Decoder::new(input);

        if let Ok(tag) = d.tag() {
            if tag.as_u64() != CALL_REQUEST_TAG {
                return Err(ParserError::InvalidCallRequest);
            }
        }

        let len = d.map()?.ok_or(ParserError::InvalidCallRequest)?;
        if len != 1 {
            return Err(ParserError::InvalidCallRequest);
        }

        let _key = d.str()?;
        // if key != "content" {
        //     return Err(ParserError::InvalidCallRequest);
        // }

        // Decode content map
        let content_len = d.map()?.ok_or(ParserError::CborUnexpected)?;
        if content_len != 6 && content_len != 7 {
            return Err(ParserError::InvalidCallRequest);
        }

        let mut nonce = None;

        for _ in 0..content_len as usize {
            let key = d.str()?;
            unsafe {
                match key {
                    "arg" => addr_of_mut!((*out).arg).write(d.bytes()?),
                    "nonce" => nonce = Some(d.bytes()?),
                    "sender" => addr_of_mut!((*out).sender).write(d.bytes()?),
                    "canister_id" => addr_of_mut!((*out).canister_id).write(d.bytes()?),
                    "method_name" => addr_of_mut!((*out).method_name).write(d.str()?),
                    "request_type" => addr_of_mut!((*out).request_type).write(d.str()?),
                    "ingress_expiry" => {
                        let n = d.u64()?;

                        addr_of_mut!((*out).ingress_expiry).write(n);
                    }
                    _ => return Err(ParserError::UnexpectedField),
                }
            }
        }
        unsafe {
            addr_of_mut!((*out).nonce).write(nonce);
        }

        Ok(&input[d.position()..])
    }
}

#[cfg(test)]
mod call_request_test {

    use super::*;

    // This is CBOR data
    const REQUEST: &str = "d9d9f7a167636f6e74656e74a6636172674c4449444c00017104746f62696b63616e69737465725f69644a00000000006000fd01016e696e67726573735f6578706972791bf710af546aca20006b6d6574686f645f6e616d656567726565746c726571756573745f747970656571756572796673656e6465724104";

    #[test]
    fn call_parse() {
        let data = hex::decode(REQUEST).unwrap();
        let call_request = CallRequest::from_bytes(&data).unwrap();
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
