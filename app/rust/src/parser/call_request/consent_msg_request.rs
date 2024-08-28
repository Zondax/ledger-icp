use core::{mem::MaybeUninit, ptr::addr_of_mut};
use minicbor::Decoder;

use crate::{
    constants::{BIG_NUM_TAG, CONSENT_MSG_REQUEST_TAG},
    error::ParserError,
    utils::{compress_leb128, hash_blob, hash_str},
    zlog, FromBytes,
};

use super::RawArg;

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
pub struct ConsentMsgRequest<'a> {
    // Bellow arg contains
    // a candid encoded type the Icrc21ConsentMessageRequest
    pub arg: RawArg<'a>,
    pub nonce: Option<&'a [u8]>,
    // Sender is allowed to be either default sender(h04) or
    // this signer
    pub sender: &'a [u8],
    pub canister_id: &'a [u8],
    pub method_name: &'a str,
    pub request_type: &'a str,
    pub ingress_expiry: u64,
}

impl<'a> ConsentMsgRequest<'a> {
    // this sums up the nonce although
    // it could be missing
    const MAP_ENTRIES: u64 = 7;

    // Getter methods (unchanged)
    pub fn arg(&self) -> &RawArg<'a> {
        &self.arg
    }

    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce
    }
    pub fn sender(&self) -> &[u8] {
        self.sender
    }
    pub fn canister_id(&self) -> &[u8] {
        self.canister_id
    }

    pub fn request_type(&self) -> &str {
        self.request_type
    }

    pub fn ingress_expiry(&self) -> u64 {
        self.ingress_expiry
    }

    /// Computes the request_id which is the hash
    /// of this struct using independent hash of structured data
    /// as described (here)[https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map]
    pub fn request_id(&self) -> [u8; 32] {
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
        let max_fields = if self.nonce.is_some() {
            MAX_FIELDS
        } else {
            MAX_FIELDS - 1
        };

        for (idx, key) in fields.iter().enumerate().take(max_fields) {
            let key_hash = hash_str(key);

            let value_hash = match idx {
                0 => hash_blob(self.request_type.as_bytes()),
                1 => hash_blob(self.sender),
                2 => {
                    let mut buf = [0u8; 10];
                    let leb = compress_leb128(self.ingress_expiry, &mut buf);
                    hash_blob(leb)
                }
                3 => hash_blob(self.canister_id),
                4 => hash_blob(self.method_name.as_bytes()),
                5 => hash_blob(self.arg.raw_data()),
                6 => {
                    if let Some(nonce) = self.nonce {
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
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        zlog("ConsentMsgRequest::from_bytes_into\x00");

        let mut d = Decoder::new(input);

        let out = out.as_mut_ptr();
        // Check tag
        if let Ok(tag) = d.tag() {
            if tag.as_u64() != CONSENT_MSG_REQUEST_TAG {
                return Err(ParserError::InvalidTag);
            }
        }

        // Decode outer map
        let len = d.map()?.ok_or(ParserError::UnexpectedValue)?;
        if len != 1 {
            return Err(ParserError::UnexpectedValue);
        }

        let _key = d.str()?;

        // Decode content map
        let content_len = d.map()?.ok_or(ParserError::UnexpectedBufferEnd)?;

        // Nonce could be an optional argument
        // so it could have 6 or 7 map entries depending
        // on the presence of nonce
        let max_entries = Self::MAP_ENTRIES;

        if content_len != max_entries && content_len != max_entries - 1 {
            return Err(ParserError::UnexpectedValue);
        }

        let mut arg = None;
        let mut nonce = None;

        for _ in 0..content_len {
            let key = d.str()?;
            unsafe {
                match key {
                    "arg" => arg = Some(d.bytes()?),
                    "nonce" => nonce = Some(d.bytes()?),
                    "sender" => addr_of_mut!((*out).sender).write(d.bytes()?),
                    "canister_id" => addr_of_mut!((*out).canister_id).write(d.bytes()?),
                    "method_name" => addr_of_mut!((*out).method_name).write(d.str()?),
                    "request_type" => addr_of_mut!((*out).request_type).write(d.str()?),
                    "ingress_expiry" => {
                        if let Ok(tag) = d.tag() {
                            if tag.as_u64() != BIG_NUM_TAG {
                                return Err(ParserError::InvalidCallRequest);
                            }
                        }

                        let Ok(bytes) = d.bytes() else {
                            return Err(ParserError::UnexpectedValue);
                        };

                        // read bytes as a timestamp of 8 bytes
                        if bytes.len() > core::mem::size_of::<u64>() {
                            return Err(ParserError::InvalidTime);
                        }

                        let mut num_bytes = [0u8; core::mem::size_of::<u64>()];
                        num_bytes[..bytes.len()].copy_from_slice(bytes);

                        let timestamp = u64::from_be_bytes(num_bytes);

                        addr_of_mut!((*out).ingress_expiry).write(timestamp);
                    }
                    _ => return Err(ParserError::UnexpectedField),
                }
            }
        }

        let arg_bytes = arg.ok_or(ParserError::CborUnexpected)?;

        let arg: &mut MaybeUninit<RawArg<'a>> = unsafe { &mut *addr_of_mut!((*out).arg).cast() };
        _ = RawArg::from_bytes_into(arg_bytes, arg)?;

        unsafe {
            addr_of_mut!((*out).nonce).write(nonce);
        }

        let out = unsafe { &mut *out };

        // This is unfortunate because of PIC issues, we can not
        // compare directli name with the METHOD_NAME constant
        let mut name = [0u8; METHOD_NAME_LEN];
        name.copy_from_slice(METHOD_NAME);

        if out.method_name.as_bytes() != name {
            return Err(ParserError::InvalidConsentMsgRequest);
        }

        Ok(&input[d.position()..])
    }
}

#[cfg(test)]
mod call_request_test {
    use crate::constants::DEFAULT_SENDER;

    use super::*;

    const REQUEST: &str = "d9d9f7a167636f6e74656e74a763617267586b4449444c076d7b6c01d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d026e036c02efcee7800401c4fbf2db05046c03d6fca70200e1edeb4a7184f7fee80a0501060c4449444c00017104746f626905677265657402656e01011e0003006b63616e69737465725f69644a00000000006000fd01016e696e67726573735f657870697279c24817c49d49c5a920806b6d6574686f645f6e616d6578246963726332315f63616e69737465725f63616c6c5f636f6e73656e745f6d657373616765656e6f6e636550a3788c1805553fb69b20f08e87e23b136c726571756573745f747970656463616c6c6673656e6465724104";
    const ARG: &str = "4449444c00017104746f6269";
    const NONCE: &str = "a3788c1805553fb69b20f08e87e23b13";
    const REQUEST_ID: &str = "4ea057c46292fedb573d35319dd1ccab3fb5d6a2b106b785d1f7757cfa5a2542";
    const CANISTER_ID: &str = "00000000006000fd0101";
    const METHOD: &str = "icrc21_canister_call_consent_message";
    const REQUEST_TYPE: &str = "call";
    // The default sender
    const INGRESS_EXPIRY: u64 = 1712666698482000000;

    #[test]
    fn msg_request() {
        let data = hex::decode(REQUEST).unwrap();
        let msg_req = ConsentMsgRequest::from_bytes(&data).unwrap();

        let request_id = hex::encode(msg_req.request_id());

        std::println!("ConsentMsgRequest: {:?}", msg_req);

        assert_eq!(hex::encode(msg_req.sender), DEFAULT_SENDER);
        assert_eq!(hex::encode(msg_req.canister_id), CANISTER_ID);
        assert_eq!(msg_req.method_name, METHOD);
        assert_eq!(msg_req.request_type, REQUEST_TYPE);

        assert_eq!(msg_req.ingress_expiry, INGRESS_EXPIRY);
        assert_eq!(hex::encode(msg_req.nonce.unwrap()), NONCE);
        assert_eq!(request_id, REQUEST_ID);
    }
}
