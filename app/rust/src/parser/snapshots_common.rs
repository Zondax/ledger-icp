use std::{
    fmt::{Debug, Display},
    prelude::v1::*,
};

use zuit::Page;

use crate::utils::strlen;

/// Executes the provided closure passing in the provided data
/// as a &'static [T].
///
/// This is really only useful to construct a type as `'static` for the purpose
/// of satisfying a bound like the one in `Viewable`
///
/// # Safety
/// `f` shouldn't store the data or rely on it being _actually_ available for the entire
/// duration of the program, but rather only have it valid for the call to the closure itself
pub unsafe fn with_leaked<'a, T: 'static, U: 'a>(
    data: Vec<T>,
    mut f: impl FnMut(&'static [T]) -> U,
) -> U {
    //this way we also drop the excess capacity
    let data = data.into_boxed_slice();

    let ptr = Box::into_raw(data);

    //it's fine to unwrap here, the pointer is aligned
    // and everything...
    let r = f(ptr.as_ref().unwrap_unchecked());

    //reclaim the box an drop it
    // this is the "unsafe" part of the function
    // because if `f` stored the data somewhere now it would be freed
    // and this isn't good, but that's why we have #Safety
    let _ = Box::from_raw(ptr);

    r
}

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

impl<'b> Debug for ReducedPage<'b> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(self, f)
    }
}
impl<'b> Display for ReducedPage<'b> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}: {:?}", self.title, self.message)
    }
}
