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
    constants::{MAX_ARGS, MAX_TABLE_FIELDS},
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

        #[cfg(test)]
        std::println!("*********MsgResponse*********:\n {}", hex::encode(input));

        // Parse Candid header
        let (rem, header) = parse_candid_header::<MAX_TABLE_FIELDS, MAX_ARGS>(input)?;

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

    const MSG_DATA: &str = "4449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e0007031e2320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e74202a2a5468651f666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f031d77697468647261772066726f6d20796f7572206163636f756e743a2a2a2272646d78362d6a616161612d61616161612d61616164712d636169202a2a596f75720d7375626163636f756e743a2a2a032330303030303030303030303030303030303030303030303030303030303030303030301d3030303030303030303030303030303030303030303030303030303030232a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a032031302049435020e29aa02054686520616c6c6f77616e63652077696c6c2062652273657420746f2031302049435020696e646570656e64656e746c79206f6620616e791e70726576696f757320616c6c6f77616e63652e20556e74696c207468697303217472616e73616374696f6e20686173206265656e206578656375746564207468651e7370656e6465722063616e207374696c6c206578657263697365207468652370726576696f757320616c6c6f77616e63652028696620616e792920746f2069742773032166756c6c20616d6f756e742e202a2a45787069726174696f6e20646174653a2a2a204e6f2065787069726174696f6e2e202a2a417070726f76616c206665653a2a2a23302e3030303120494350202a2a5472616e73616374696f6e206665657320746f206265031a7061696420627920796f7572207375626163636f756e743a2a2a2330303030303030303030303030303030303030303030303030303030303030303030301d3030303030303030303030303030303030303030303030303030303030";

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
