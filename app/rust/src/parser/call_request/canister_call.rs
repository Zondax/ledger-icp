use core::{mem::MaybeUninit, ptr::addr_of_mut};

use minicbor::Decoder;

use crate::{
    constants::{BIG_NUM_TAG, CANISTER_CALL_TAG},
    error::ParserError,
    zlog, FromBytes,
};

use super::RawArg;

#[derive(PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct CanisterCall<'a> {
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

impl CanisterCall<'_> {
    // this sums up the nonce although
    // it could be missing
    //
    const MAP_ENTRIES: u64 = 7;

    pub fn arg(&self) -> &RawArg {
        &self.arg
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
}

impl<'a> FromBytes<'a> for CanisterCall<'a> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        zlog("CanisterCall::from_bytes_into\x00");

        let mut d = Decoder::new(input);

        let out = out.as_mut_ptr();
        // Check tag
        if let Ok(tag) = d.tag() {
            if tag.as_u64() != CANISTER_CALL_TAG {
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

        let mut nonce = None;

        for _ in 0..content_len {
            let key = d.str()?;
            unsafe {
                match key {
                    "arg" => {
                        let arg: &mut MaybeUninit<RawArg<'a>> =
                            &mut *addr_of_mut!((*out).arg).cast();
                        let arg_bytes = d.bytes()?;
                        _ = RawArg::from_bytes_into(arg_bytes, arg)?;
                    }
                    "nonce" => nonce = Some(d.bytes()?),
                    "sender" => addr_of_mut!((*out).sender).write(d.bytes()?),
                    "canister_id" => addr_of_mut!((*out).canister_id).write(d.bytes()?),
                    "method_name" => addr_of_mut!((*out).method_name).write(d.str()?),
                    "request_type" => addr_of_mut!((*out).request_type).write(d.str()?),
                    "ingress_expiry" => {
                        let timestamp = if let Ok(n) = d.u64() {
                            // Direct uint64 case (what we have in the data)
                            n
                        } else {
                            d.set_position(d.position() - 1);
                            let tag = d.tag()?;
                            // Your existing tagged bignum case
                            if tag.as_u64() != BIG_NUM_TAG {
                                return Err(ParserError::InvalidCallRequest);
                            }
                            let bytes = d.bytes()?;
                            if bytes.len() > core::mem::size_of::<u64>() {
                                return Err(ParserError::InvalidTime);
                            }
                            let mut num_bytes = [0u8; core::mem::size_of::<u64>()];
                            num_bytes[..bytes.len()].copy_from_slice(bytes);
                            u64::from_be_bytes(num_bytes)
                        };

                        addr_of_mut!((*out).ingress_expiry).write(timestamp);
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
