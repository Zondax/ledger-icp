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
use core::mem::MaybeUninit;

use crate::{
    candid_header::CandidHeader,
    error::{ParserError, ViewError},
};

pub mod call_request;
pub mod candid_utils;
mod certificate;
pub mod consent_message;
#[cfg(test)]
mod snapshots_common;

pub use certificate::*;

pub trait FromCandidHeader<'a> {
    fn from_candid_header<const MAX_ARGS: usize>(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
        header: &CandidHeader<MAX_ARGS>,
    ) -> Result<&'a [u8], ParserError>
    where
        Self: Sized;
}

///This trait defines an useful interface to parse
///objects from bytes.
///this gives different objects in a transaction
///a way to define their own deserilization implementation, allowing higher level objects to generalize the
///parsing of their inner types
pub trait FromBytes<'b>: Sized {
    /// this method is avaliable for testing only, as the preferable
    /// option is to save stack by passing the memory where the object should
    /// store itself
    #[cfg(test)]
    fn from_bytes(input: &'b [u8]) -> Result<Self, crate::error::ParserError> {
        let mut out = MaybeUninit::uninit();
        Self::from_bytes_into(input, &mut out)?;
        unsafe { Ok(out.assume_init()) }
    }

    ///Main deserialization method
    ///`input` the input data that contains the serialized form in bytes of this object.
    ///`out` the memory where this object would be stored
    ///
    /// returns the remaining bytes on success
    ///
    /// `Safety` Dealing with uninitialize memory is undefine behavior
    /// even in rust, so implementors should follow the rust documentation
    /// for MaybeUninit and unsafe guidelines.
    ///
    /// It's a good idea to always put `#[inline(never)]` on top of this
    /// function's implementation
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], crate::error::ParserError>;
}

pub trait FromTable<'a>: Sized {
    fn from_table(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
        type_table: &crate::type_table::TypeTable,
        type_index: usize,
    ) -> Result<&'a [u8], crate::error::ParserError>;
}

///This trait defines the interface useful in the UI context
/// so that all the different OperationTypes or other items can handle their own UI
pub trait DisplayableItem {
    /// Returns the number of items to display
    fn num_items(&self) -> Result<u8, ViewError>;

    /// This is invoked when a given page is to be displayed
    ///
    /// `item_n` is the item of the operation to display;
    /// guarantee: 0 <= item_n < self.num_items()
    /// `title` is the title of the item
    /// `message` is the contents of the item
    /// `page` is what page we are supposed to display, this is used to split big messages
    ///
    /// returns the total number of pages on success
    ///
    /// It's a good idea to always put `#[inline(never)]` on top of this
    /// function's implementation
    //#[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError>;
}
