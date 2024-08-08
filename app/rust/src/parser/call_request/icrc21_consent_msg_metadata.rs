use core::ptr::addr_of_mut;

use crate::{
    candid_utils::{parse_opt_i16, parse_text},
    error::ParserError,
    utils::{compress_sleb128, hash, hash_str},
    FromBytes,
};

#[repr(C)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Icrc21ConsentMessageMetadata<'a> {
    pub language: &'a str,
    pub utc_offset_minutes: Option<i16>,
}

impl<'a> Icrc21ConsentMessageMetadata<'a> {
    // Hashing function for Icrc21ConsentMessageMetadata
    pub fn hash(&self) -> [u8; 32] {
        let mut field_hashes = [[0u8; 64]; 2];
        let mut field_count = 0;

        field_hashes[field_count][..32].copy_from_slice(&hash_str("language"));
        field_hashes[field_count][32..].copy_from_slice(&hash_str(self.language));
        field_count += 1;

        // according to docs, we include the hash
        // only if it is Some
        if let Some(offset) = self.utc_offset_minutes {
            let mut buf = [0u8; 10];
            let offset_leb128 = compress_sleb128(offset as i64, &mut buf);
            field_hashes[field_count][..32].copy_from_slice(&hash_str("utc_offset_minutes"));
            field_hashes[field_count][32..].copy_from_slice(&hash(offset_leb128));
            field_count += 1;
        }

        field_hashes[..field_count].sort_unstable();

        let mut concatenated = [0u8; 128];
        for (i, hash) in field_hashes[..field_count].iter().enumerate() {
            concatenated[i * 64..(i + 1) * 64].copy_from_slice(hash);
        }

        hash(&concatenated[..field_count * 64])
    }
}

impl<'a> FromBytes<'a> for Icrc21ConsentMessageMetadata<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        // Parse language (text)
        let (rem, language) = parse_text(input)?;
        if language.is_empty() {
            return Err(ParserError::InvalidLanguage);
        }

        // Parse utc_offset_minutes (opt int16)
        let (rem, utc_offset_minutes) = parse_opt_i16(rem)?;

        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).language).write(language);
            addr_of_mut!((*out).utc_offset_minutes).write(utc_offset_minutes);
        }
        Ok(rem)
    }
}
