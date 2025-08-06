/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use core::ptr::addr_of_mut;

use crate::{
    candid_header::parse_candid_header,
    constants::MAX_ARGS,
    error::{ParserError, ViewError},
    utils::decompress_leb128,
    DisplayableItem, FromBytes, FromCandidHeader,
};

use super::{msg_error::Error, msg_info::ConsentInfo};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum ResponseType {
    Ok,
    Err,
}

impl TryFrom<u64> for ResponseType {
    type Error = ParserError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Err),
            _ => Err(ParserError::InvalidResponseType),
        }
    }
}

#[repr(C)]
struct OkVariant<'a>(ResponseType, ConsentInfo<'a>);

#[repr(C)]
struct ErrVariant<'a>(ResponseType, Error<'a>);

#[repr(u8)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub enum ConsentMessageResponse<'a> {
    Ok(ConsentInfo<'a>),
    Err(Error<'a>),
}

impl<'a> ConsentMessageResponse<'a> {
    pub const OK_HASH: u32 = 17724; // hash of "Ok"
    pub const ERR_HASH: u32 = 3456837; // hash of Err

    pub fn response_type(&self) -> ResponseType {
        match self {
            Self::Ok(_) => ResponseType::Ok,
            Self::Err(_) => ResponseType::Err,
        }
    }

    pub fn consent_info(&self) -> Option<&ConsentInfo<'a>> {
        match self {
            Self::Ok(info) => Some(info),
            _ => None,
        }
    }
}

impl<'a> FromBytes<'a> for ConsentMessageResponse<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        crate::zlog("ConsentMessageResponse::from_bytes_into");

        // Parse Candid header
        let (rem, header) = parse_candid_header::<MAX_ARGS>(input)?;

        // Read the variant index
        let (rem, variant_index) = decompress_leb128(rem)?;

        // Get the root variant type (type 0)
        let root_entry = header
            .type_table
            .find_type_entry(0)
            .ok_or(ParserError::UnexpectedType)?;

        if variant_index >= root_entry.field_count as u64 {
            return Err(ParserError::UnexpectedType);
        }
        
        // Additional safety check for our reduced array size
        if variant_index >= crate::constants::MAX_FIELDS_PER_TYPE as u64 {
            return Err(ParserError::UnexpectedType);
        }

        let (field_hash, _) = root_entry.fields[variant_index as usize];

        match field_hash {
            Self::OK_HASH => {
                let out = out.as_mut_ptr() as *mut OkVariant;
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };
                let rem = ConsentInfo::from_candid_header(rem, data, &header)?;
                unsafe {
                    addr_of_mut!((*out).0).write(ResponseType::Ok);
                }
                Ok(rem)
            }
            Self::ERR_HASH => {
                let out = out.as_mut_ptr() as *mut ErrVariant;
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };
                let rem = Error::from_candid_header(rem, data, &header)?;
                unsafe {
                    addr_of_mut!((*out).0).write(ResponseType::Err);
                }
                Ok(rem)
            }
            _ => Err(ParserError::UnexpectedType),
        }
    }
}

impl DisplayableItem for ConsentMessageResponse<'_> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        match self {
            Self::Ok(msg) => msg.num_items(),
            Self::Err(err) => err.num_items(),
        }
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match self {
            Self::Ok(msg) => msg.render_item(item_n, title, message, page),
            Self::Err(_) => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod msg_response_test {
    use serde::{Deserialize, Serialize};
    use std::string::String;
    use zemu_sys::Viewable;

    use crate::{parser::snapshots_common::ReducedPage, test_ui::with_leaked};

    use super::*;

    const MSG_DATA: &str = "4449444c0f6b02bc8a0101c5fed2010c6c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b029ee0b53b05fcdfd79a0f716c02f99cba840806dcec99f409716d076c02007101086b04cdf1cbbe030991c38ee7040ae998e3c30a0bebd2e8d60f0b6c01b99adecb01716c03c295a993017bd8a38ca80d78d8def6f60e716c01d8a38ca80d786b04d1c4987c0da3f2efe6020e9a8597e6030ee3c581900f0e6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e00040455736572000d48656c6c6f2c20776f726c64210a637265617465645f617402f0bc7068000000000a6163746976655f666f7203580200000000000006616d6f756e74010800c2eb0b00000000034943500a47726565742075736572";

    #[derive(Serialize, Deserialize, Debug)]
    struct TransactionData {
        response: String,
    }

    /// This is only to be used for testing, hence why
    /// it's present inside the `mod test` block only
    impl Viewable for ConsentMessageResponse<'_> {
        fn num_items(&mut self) -> Result<u8, zemu_sys::ViewError> {
            DisplayableItem::num_items(&*self).map_err(|_| zemu_sys::ViewError::Unknown)
        }

        fn render_item(
            &mut self,
            item_idx: u8,
            title: &mut [u8],
            message: &mut [u8],
            page_idx: u8,
        ) -> Result<u8, zemu_sys::ViewError> {
            DisplayableItem::render_item(&*self, item_idx, title, message, page_idx)
                .map_err(|_| zemu_sys::ViewError::Unknown)
        }

        fn accept(&mut self, _: &mut [u8]) -> (usize, u16) {
            (0, 0)
        }

        fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
            (0, 0)
        }
    }

    #[test]
    fn parse_msg_response() {
        let data = hex::decode(MSG_DATA).unwrap();
        let _ = ConsentMessageResponse::from_bytes(&data[..]).unwrap();
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_ui() {
        insta::glob!("testvectors/*.json", |path| {
            let file = std::fs::File::open(path)
                .unwrap_or_else(|e| panic!("Unable to open file {:?}: {:?}", path, e));
            let input: TransactionData = serde_json::from_reader(file)
                .unwrap_or_else(|e| panic!("Unable to read file {:?} as json: {:?}", path, e));

            let test = |data| {
                let resp = ConsentMessageResponse::from_bytes(data).expect("Fail parsing");

                let mut driver = zuit::MockDriver::<_, 18, 1024>::new(resp);
                driver.drive();

                let ui = driver.out_ui();

                let reduced = ui
                    .iter()
                    .flat_map(|item| item.iter().map(ReducedPage::from))
                    .collect::<std::vec::Vec<_>>();

                insta::assert_debug_snapshot!(reduced);
            };

            let data = hex::decode(input.response).unwrap();

            unsafe { with_leaked(data, test) };
        });
    }
}
