use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::{error::ParserError, utils::compress_leb128, zlog, FromBytes};

use super::{CanisterCall, RawArg};

// {"content": {"arg": h'4449444C00017104746F6269', "canister_id": h'00000000006000FD0101',
// "ingress_expiry": 1712667140606000000, "method_name": "greet", "request_type": "query", "sender": h'04'}}
#[derive(PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct CallRequest<'a>(CanisterCall<'a>);

impl<'a> CallRequest<'a> {
    pub fn arg(&'a self) -> &RawArg<'a> {
        self.0.arg()
    }
    pub fn sender(&self) -> &[u8] {
        self.0.sender()
    }
    pub fn canister_id(&self) -> &[u8] {
        self.0.canister_id()
    }
    pub fn method_name(&self) -> &str {
        self.0.method_name()
    }
    pub fn request_type(&self) -> &str {
        self.0.request_type()
    }
    pub fn ingress_expiry(&self) -> u64 {
        self.0.ingress_expiry()
    }

    pub fn nonce(&self) -> Option<&[u8]> {
        self.0.nonce()
    }

    // Compute the hash of the call request
    // this is going to be signed
    // order of the fields is important
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = sha2::Sha256::new();

        // Helper function to hash a field
        let mut hash_field = |name: &str, value: &[u8]| {
            let tmp: [u8; 32] = Sha256::digest(name.as_bytes()).into();
            hasher.update(tmp);
            let tmp: [u8; 32] = Sha256::digest(value).into();
            hasher.update(tmp);
        };

        // Hash fields in the same order as the C function
        hash_field("sender", self.sender());
        hash_field("canister_id", self.canister_id());

        // Hash ingress_expiry (u64)
        let mut buf = [0u8; 10];
        hash_field(
            "ingress_expiry",
            compress_leb128(self.ingress_expiry(), &mut buf),
        );

        hash_field("method_name", self.method_name().as_bytes());
        hash_field("request_type", self.request_type().as_bytes());

        // Hash nonce if present
        if let Some(nonce) = self.nonce() {
            hash_field("nonce", nonce);
        }

        // Hash arg last
        hash_field("arg", self.arg().raw_data());

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
    ) -> Result<&'a [u8], ParserError> {
        zlog("CallRequest::from_bytes_into\x00");
        let out = out.as_mut_ptr();

        let call: &mut MaybeUninit<CanisterCall<'a>> =
            unsafe { &mut *addr_of_mut!((*out).0).cast() };

        let rem = CanisterCall::from_bytes_into(input, call)?;

        Ok(rem)
    }
}

#[cfg(test)]
mod call_request_test {

    use super::*;

    const REQUEST: &str = "d9d9f7a167636f6e74656e74a76361726758684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b18072a6f7894d0006b6d6574686f645f6e616d656d69637263325f617070726f7665656e6f6e6365506b99f1c2338b4543152aae206d5286726c726571756573745f747970656463616c6c6673656e646572581d052c5f6f270fc4a3a882a8075732cba90ad4bd25d30bd2cf7b0bfe7c02";
    const TIME_EXPIRY: u64 = 1731399240000000000;
    const CANISTER_ID: &str = "00000000000000020101";

    const ARG: &str =  "4449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a0000000000000007010100";
    const SENDER: &str = "052c5f6f270fc4a3a882a8075732cba90ad4bd25d30bd2cf7b0bfe7c02";
    const METHOD_NAME: &str = "icrc2_approve";
    const REQUEST_TYPE: &str = "call";

    #[test]
    fn call_parse4() {
        let data = hex::decode(REQUEST).unwrap();
        let call_request = CallRequest::from_bytes(&data).unwrap();

        assert_eq!(hex::encode(call_request.arg().raw_data()), ARG);
        // Sender in this tests is not the default one
        assert_eq!(hex::encode(call_request.sender()), SENDER);
        assert_eq!(hex::encode(call_request.canister_id()), CANISTER_ID);
        assert_eq!(call_request.method_name(), METHOD_NAME);
        assert_eq!(call_request.request_type(), REQUEST_TYPE);
        assert_eq!(call_request.ingress_expiry(), TIME_EXPIRY);
    }
}
