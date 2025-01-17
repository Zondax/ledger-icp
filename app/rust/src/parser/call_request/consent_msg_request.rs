use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::{
    error::ParserError,
    utils::{compress_leb128, hash_blob, hash_str},
    zlog, FromBytes,
};

use super::{CanisterCall, Icrc21ConsentMessageRequest, RawArg};

const METHOD_NAME_LEN: usize = 36;
const METHOD_NAME: &[u8] = b"icrc21_canister_call_consent_message";

/// This struct holds the canister call consent message request
/// and tier the icrc21_message_request which is candid encoded
/// as part of the arg blob.
// {"content": {"arg": h'4449444C076D7B6C01D880C6D007716C02CBAEB581017AB183E7F1077A6B028BEABFC2067F8EF1C1EE0D026E036C02EFCEE7800401C4FBF2DB05046C03D6FCA70200E1EDEB4A7184F7FEE80A0501060C4449444C00017104746F626905677265657402656E01011E000300',
// "canister_id": h'00000000006000FD0101', "ingress_expiry": 1712666698482000000,
// "method_name": "icrc21_canister_call_consent_message", "nonce": h'A3788C1805553FB69B20F08E87E23B13',
// "request_type": "call", "sender": h'04'}}
#[derive(PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct ConsentMsgRequest<'a>(CanisterCall<'a>);

impl ConsentMsgRequest<'_> {
    // this sums up the nonce although
    // it could be missing
    const MAP_ENTRIES: u64 = 7;

    // Getter methods (unchanged)
    pub fn arg(&self) -> &RawArg<'_> {
        self.0.arg()
    }

    pub fn nonce(&self) -> Option<&[u8]> {
        self.0.nonce()
    }
    pub fn sender(&self) -> &[u8] {
        self.0.sender()
    }
    pub fn canister_id(&self) -> &[u8] {
        self.0.canister_id()
    }

    pub fn request_type(&self) -> &str {
        self.0.request_type()
    }

    pub fn ingress_expiry(&self) -> u64 {
        self.0.ingress_expiry()
    }

    pub fn method_name(&self) -> &str {
        self.0.method_name()
    }

    #[inline(never)]
    pub fn icrc21_msg_request(&self) -> Result<Icrc21ConsentMessageRequest, ParserError> {
        // lazy parsing on demand in order to reduce stack usage
        Ok(Icrc21ConsentMessageRequest::new_unchecked(
            self.arg().raw_data(),
        ))
    }

    /// Computes the request_id which is the hash
    /// of this struct using independent hash of structured data
    /// as described (here)[https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map]
    #[inline(never)]
    pub fn request_id(&self) -> [u8; 32] {
        crate::zlog("ConsentMsgRequest::request_id\x00");

        const MAX_FIELDS: usize = 7;
        let fields: [&str; MAX_FIELDS] = [
            "request_type",
            "sender",
            "ingress_expiry",
            "canister_id",
            "method_name",
            "arg",
            "nonce",
        ];
        let mut field_hashes = [[0u8; 64]; MAX_FIELDS];
        let mut field_count = 0;
        let max_fields = if self.0.nonce().is_some() {
            MAX_FIELDS
        } else {
            MAX_FIELDS - 1
        };

        for (idx, key) in fields.iter().enumerate().take(max_fields) {
            let key_hash = hash_str(key);

            let value_hash = match idx {
                0 => hash_blob(self.0.request_type.as_bytes()),
                1 => hash_blob(self.0.sender),
                2 => {
                    let mut buf = [0u8; 10];
                    let leb = compress_leb128(self.0.ingress_expiry, &mut buf);
                    hash_blob(leb)
                }
                3 => hash_blob(self.0.canister_id()),
                4 => hash_blob(self.0.method_name().as_bytes()),
                5 => hash_blob(self.0.arg.raw_data()),
                6 => {
                    if let Some(nonce) = self.0.nonce {
                        hash_blob(nonce)
                    } else {
                        break;
                    }
                }
                _ => unreachable!(),
            };

            field_hashes[field_count][..32].copy_from_slice(&key_hash);
            field_hashes[field_count][32..].copy_from_slice(&value_hash);
            field_count += 1;
        }

        field_hashes[..field_count].sort_unstable();
        let mut concatenated = [0u8; MAX_FIELDS * 64];

        // omit Nonce if no present
        for (i, hash) in field_hashes[..field_count].iter().enumerate() {
            concatenated[i * 64..(i + 1) * 64].copy_from_slice(hash);
        }
        hash_blob(&concatenated[..field_count * 64])
    }
}

impl<'a> FromBytes<'a> for ConsentMsgRequest<'a> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        zlog("ConsentMsgRequest::from_bytes_into\x00");

        let out = out.as_mut_ptr();

        let call: &mut MaybeUninit<CanisterCall<'a>> =
            unsafe { &mut *addr_of_mut!((*out).0).cast() };

        let rem = CanisterCall::from_bytes_into(input, call)?;

        let out = unsafe { &mut *out };

        // This is unfortunate because of PIC issues, we can not
        // compare directly name with the METHOD_NAME constant
        let mut name = [0u8; METHOD_NAME_LEN];
        name.copy_from_slice(METHOD_NAME);

        if out.0.method_name.as_bytes() != name {
            return Err(ParserError::InvalidConsentMsgRequest);
        }

        crate::zlog("ConsentMsgRequest::from_bytes_into ok\x00");
        Ok(rem)
    }
}

#[cfg(test)]
mod call_request_test {
    use crate::constants::DEFAULT_SENDER;

    use super::*;

    const REQUEST: &str = "d9d9f7a167636f6e74656e74a76361726758d84449444c086d7b6e766c02aeaeb1cc0501d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d036e046c02efcee7800402c4fbf2db05056c03d6fca70200e1edeb4a7184f7fee80a060107684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101000d69637263325f617070726f76650002656e0101230003006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b18072a6f7894d0006b6d6574686f645f6e616d6578246963726332315f63616e69737465725f63616c6c5f636f6e73656e745f6d657373616765656e6f6e636550369f1914fd64438f5e6329fcb66b1d4d6c726571756573745f747970656463616c6c6673656e6465724104";

    const ARG: &str = "4449444c00017104746f6269";
    const NONCE: &str = "369f1914fd64438f5e6329fcb66b1d4d";
    const REQUEST_ID: &str = "ea37fdc5229d7273d500dc8ae3c009f0421049c1f02cc5ad85ea838ae7dfc045";
    const CANISTER_ID: &str = "00000000000000020101";
    const METHOD: &str = "icrc21_canister_call_consent_message";
    const REQUEST_TYPE: &str = "call";
    // The default sender
    const INGRESS_EXPIRY: u64 = 1731399240000000000;

    #[test]
    fn msg_request() {
        let data = hex::decode(REQUEST).unwrap();
        let msg_req = ConsentMsgRequest::from_bytes(&data).unwrap();

        let icrc_msg_request = msg_req.icrc21_msg_request().unwrap();

        let method = icrc_msg_request.method().unwrap();
        assert_eq!(method, "icrc2_approve");

        let request_id = hex::encode(msg_req.request_id());

        assert_eq!(msg_req.sender().len(), 1);
        assert_eq!(msg_req.sender()[0], DEFAULT_SENDER);
        assert_eq!(hex::encode(msg_req.canister_id()), CANISTER_ID);
        assert_eq!(msg_req.method_name(), METHOD);
        assert_eq!(msg_req.request_type(), REQUEST_TYPE);
        std::println!("request_id: {}", request_id);

        assert_eq!(msg_req.ingress_expiry(), INGRESS_EXPIRY);
        assert_eq!(hex::encode(msg_req.nonce().unwrap()), NONCE);
        assert_eq!(request_id, REQUEST_ID);
    }
}
