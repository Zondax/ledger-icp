use core::ptr::addr_of_mut;

use crate::{
    candid_utils::{parse_bytes, parse_text},
    error::ParserError,
    utils::{decompress_leb128, hash, hash_blob, hash_str},
    FromBytes,
};

use super::Icrc21ConsentMessageSpec;

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Icrc21ConsentMessageRequest<'a> {
    method: &'a str,
    arg: &'a [u8],
    user_preferences: Icrc21ConsentMessageSpec<'a>,
}

impl<'a> Icrc21ConsentMessageRequest<'a> {
    pub fn method(&self) -> &str {
        self.method
    }
    pub fn arg(&self) -> &[u8] {
        self.arg
    }

    pub fn user_preferences(&self) -> &Icrc21ConsentMessageSpec<'a> {
        &self.user_preferences
    }

    /// Computes the request_id which is the hash
    /// of this struct using independent hash of structured data
    /// as described (here)[https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map]
    pub fn request_id(&self) -> [u8; 32] {
        let mut field_hashes = [[0u8; 64]; 3];
        let mut field_count = 0;

        field_hashes[field_count][..32].copy_from_slice(&hash_str("method"));
        field_hashes[field_count][32..].copy_from_slice(&hash_str(self.method));
        field_count += 1;

        field_hashes[field_count][..32].copy_from_slice(&hash_str("arg"));
        field_hashes[field_count][32..].copy_from_slice(&hash_blob(self.arg));
        field_count += 1;

        field_hashes[field_count][..32].copy_from_slice(&hash_str("user_preferences"));
        field_hashes[field_count][32..].copy_from_slice(&self.user_preferences.hash());
        field_count += 1;

        field_hashes[..field_count].sort_unstable();

        let mut concatenated = [0u8; 192];
        for (i, hash) in field_hashes[..field_count].iter().enumerate() {
            concatenated[i * 64..(i + 1) * 64].copy_from_slice(hash);
        }

        hash(&concatenated[..field_count * 64])
    }
}

impl<'a> FromBytes<'a> for Icrc21ConsentMessageRequest<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("Icrc21ConsentMessageRequest::from_bytes_into");

        // skip type information of args
        let (rem, _) = decompress_leb128(input)?;
        let (rem, _) = decompress_leb128(rem)?;

        let (rem, bytes) = parse_bytes(rem)?;

        let (rem, method) = parse_text(rem)?;

        let out = out.as_mut_ptr();
        #[cfg(test)]
        std::println!("input_spec: {}", hex::encode(rem));

        // Field with hash 1075439471 points to type 2 the metadata
        let preferences = unsafe { &mut *addr_of_mut!((*out).user_preferences).cast() };
        let rem = Icrc21ConsentMessageSpec::from_bytes_into(rem, preferences)?;

        unsafe {
            // skip tag
            addr_of_mut!((*out).arg).write(bytes);
            addr_of_mut!((*out).method).write(method);
        }

        Ok(rem)
    }
}
