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
use crate::{error::ParserError, FromBytes};
use core::ptr::addr_of_mut;

use super::{msg::ConsentMessage, msg_metadata::ConsentMessageMetadata};

#[derive(Debug)]
#[repr(C)]
pub struct ConsentInfo<'a> {
    pub message: ConsentMessage<'a>,
    pub metadata: ConsentMessageMetadata<'a>,
}

impl<'a> FromBytes<'a> for ConsentInfo<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], ParserError> {
        let out = out.as_mut_ptr();
        let message = unsafe { &mut *addr_of_mut!((*out).message).cast() };
        let rem = ConsentMessage::from_bytes_into(input, message)?;

        let metadata = unsafe { &mut *addr_of_mut!((*out).metadata).cast() };
        let rem = ConsentMessageMetadata::from_bytes_into(rem, metadata)?;

        Ok(rem)
    }
}
