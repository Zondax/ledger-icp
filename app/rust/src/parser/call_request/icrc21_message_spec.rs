use core::ptr::addr_of_mut;

use crate::{
    error::ParserError,
    utils::{compress_leb128, decompress_leb128, hash, hash_str},
    FromBytes,
};

use super::Icrc21ConsentMessageMetadata;

type Hash256 = [u8; 32];

#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Icrc21ConsentMessageSpec<'a> {
    metadata: Icrc21ConsentMessageMetadata<'a>,
    device_spec: Option<DeviceSpec>,
}

impl<'a> Icrc21ConsentMessageSpec<'a> {
    // Hashing function for Icrc21ConsentMessageSpec
    pub fn hash(&self) -> [u8; 32] {
        let mut field_hashes = [[0u8; 64]; 2];
        let mut field_count = 0;

        field_hashes[field_count][..32].copy_from_slice(&hash_str("metadata"));
        field_hashes[field_count][32..].copy_from_slice(&self.metadata.hash());
        field_count += 1;

        if let Some(device_spec) = &self.device_spec {
            field_hashes[field_count][..32].copy_from_slice(&hash_str("device_spec"));
            field_hashes[field_count][32..].copy_from_slice(&device_spec.hash());
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

// device_spec: opt variant {
//         // A generic display able to handle large documents and do line wrapping and pagination / scrolling.
//         // Text must be Markdown formatted, no external resources (e.g. images) are allowed.
//         GenericDisplay;
//         // Simple display able to handle lines of text with a maximum number of characters per line.
//         // Multiple pages can be used if the text does no fit on a single page.
//         // Text must be plain text without any embedded formatting elements.
//         LineDisplay: record {
//             // Maximum number of characters that can be displayed per line.
//             characters_per_line: nat16;
//             // Maximum number of lines that can be displayed at once on a single page.
//             lines_per_page: nat16;
//         };
//     };
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum DeviceSpec {
    GenericDisplay,
    LineDisplay {
        characters_per_line: u16,
        lines_per_page: u16,
    },
}

impl DeviceSpec {
    // Hashing function for DeviceSpec
    pub fn hash(&self) -> [u8; 32] {
        match self {
            DeviceSpec::GenericDisplay => hash_str("GenericDisplay"),
            DeviceSpec::LineDisplay {
                characters_per_line,
                lines_per_page,
            } => {
                let mut field_hashes = [[0u8; 64]; 2];
                let mut field_count = 0;

                let mut buf = [0u8; 10];
                let characters_per_line_leb128 =
                    compress_leb128(*characters_per_line as u64, &mut buf);
                field_hashes[field_count][..32].copy_from_slice(&hash_str("characters_per_line"));
                field_hashes[field_count][32..].copy_from_slice(&hash(characters_per_line_leb128));
                field_count += 1;

                let lines_per_page_leb128 = compress_leb128(*lines_per_page as u64, &mut buf);
                field_hashes[field_count][..32].copy_from_slice(&hash_str("lines_per_page"));
                field_hashes[field_count][32..].copy_from_slice(&hash(lines_per_page_leb128));
                field_count += 1;

                field_hashes[..field_count].sort_unstable();

                let mut concatenated = [0u8; 128];
                for (i, hash) in field_hashes[..field_count].iter().enumerate() {
                    concatenated[i * 64..(i + 1) * 64].copy_from_slice(hash);
                }

                hash(&concatenated[..field_count * 64])
            }
        }
    }
}

impl<'a> FromBytes<'a> for Icrc21ConsentMessageSpec<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("Icrc21ConsentMessageSpec::from_bytes_into");

        let out = out.as_mut_ptr() as *mut Icrc21ConsentMessageSpec;
        // Field with hash 1075439471 points to type 2 the metadata
        let metadata = unsafe { &mut *addr_of_mut!((*out).metadata).cast() };
        let rem = Icrc21ConsentMessageMetadata::from_bytes_into(input, metadata)?;
        #[cfg(test)]
        std::println!("Metadata");
        let (rem, variant) = decompress_leb128(rem).map_err(|_| ParserError::UnexpectedError)?;
        #[cfg(test)]
        std::println!("device_spec_variant: {}", variant);

        Ok(rem)
    }
}
