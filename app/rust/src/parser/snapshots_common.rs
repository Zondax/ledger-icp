use std::{
    fmt::{Debug, Display},
    prelude::v1::*,
};

use zuit::Page;

use crate::utils::strlen;

/// This struct is useful to have more concise output a certain page
///
/// By default, to construct this you'd use `from` and the implementation will
/// try to parse the title and message of the page as UTF8 to display those
///
/// The Debug impl is based on Display and is of the format `"{title}": "{message}"`
pub struct ReducedPage<'b> {
    title: &'b str,
    message: &'b str,
}

impl<'b, const T: usize, const M: usize> From<&'b Page<T, M>> for ReducedPage<'b> {
    fn from(page: &'b Page<T, M>) -> Self {
        let tlen = strlen(&page.title);
        let title = std::str::from_utf8(&page.title[..tlen]).expect("title was not valid utf8");

        let mlen = strlen(&page.message);
        let message =
            std::str::from_utf8(&page.message[..mlen]).expect("message was not valid utf8");

        ReducedPage { title, message }
    }
}

impl Debug for ReducedPage<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(self, f)
    }
}
impl Display for ReducedPage<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}: {:?}", self.title, self.message)
    }
}
