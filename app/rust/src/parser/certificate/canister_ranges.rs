use core::{mem::MaybeUninit, ptr::addr_of_mut};

use minicbor::Decoder;

use crate::{constants::CANISTER_RANGES_TAG, error::ParserError, FromBytes};

const CANISTER_RANGE_SIZE: usize = 2;
const MAX_PRINCIPAL_SIZE: usize = 29;

#[derive(Debug, Clone, Copy)]
pub struct CanisterRanges<'a> {
    len: usize,
    data: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct CanisterRangeIterator<'a> {
    len: usize,
    current: usize,
    data: &'a [u8],
}

impl<'a> CanisterRanges<'a> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        CanisterRangeIterator {
            len: self.len,
            current: 0,
            data: self.data,
        }
    }
}

impl<'a> FromBytes<'a> for CanisterRanges<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let mut d = Decoder::new(input);

        // Check for the expected tag
        if let Ok(tag) = d.tag() {
            if tag.as_u64() != CANISTER_RANGES_TAG {
                return Err(ParserError::InvalidCanisterId);
            }
        }

        // Get the length of the outer array (number of ranges)
        let num_ranges = d
            .array()
            .map_err(|_| ParserError::MiniCborError)?
            .ok_or(ParserError::UnexpectedType)? as usize;

        let start = d.position();

        // Parse each canister_range
        for _ in 0..num_ranges {
            // Each canister_range is an array of two principals
            let len = d
                .array()
                .map_err(|_| ParserError::MiniCborError)?
                .ok_or(ParserError::UnexpectedType)?;

            if len != CANISTER_RANGE_SIZE as u64 {
                return Err(ParserError::InvalidCanisterId);
            }

            for _ in 0..CANISTER_RANGE_SIZE {
                // Parse two principals (start and end of range)
                let principal = d.bytes().map_err(|_| ParserError::InvalidCanisterId)?;
                if principal.len() > MAX_PRINCIPAL_SIZE {
                    return Err(ParserError::InvalidCanisterId);
                }
            }
        }

        let end = d.position();

        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).len).write(num_ranges);
            addr_of_mut!((*out).data).write(&input[start..end]);
        }

        Ok(&input[end..])
    }
}

// canister_ranges = tagged<[*canister_range]>
// canister_range = [principal principal]
// principal = bytes .size (0..29)
// tagged<t> = #6.55799(t) ; the CBOR tag
impl<'a> Iterator for CanisterRangeIterator<'a> {
    type Item = (&'a [u8], &'a [u8]); // Each item is a pair of principals or an error

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.data.len() {
            return None;
        }

        let mut d = Decoder::new(&self.data[self.current..]);

        // Each canister_range is an array of two principals
        // range = [start, end]
        d.array().ok()?;

        let range_start = d.bytes().ok()?;

        let range_end = d.bytes().ok()?;

        self.current += d.position();

        Some((range_start, range_end))
    }
}
