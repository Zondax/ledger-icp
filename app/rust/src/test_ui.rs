#![cfg(test)]
use std::fmt::Debug;
use std::fmt::Display;
use std::println;
use std::vec::Vec;

use std::boxed::Box;

use std::vec;

use crate::error::ParserError;

pub trait Viewable: Sized {
    /// Returns the number of items to display
    fn num_items(&self) -> Result<u8, ParserError>;

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
    ) -> Result<u8, ParserError>;

    fn accept(&mut self, _: &mut [u8]) -> (usize, u16) {
        (0, 0)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        (0, 0)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Page<const T: usize, const M: usize> {
    pub title: [u8; T],
    pub message: [u8; M],
}

impl<const T: usize, const M: usize> Default for Page<T, M> {
    fn default() -> Self {
        Self {
            title: [0; T],
            message: [0; M],
        }
    }
}

/// This struct will render each item and each page of an item of a given `viewable`
pub struct MockDriver<V, const T: usize, const M: usize> {
    viewable: Box<V>,
    print: bool,

    //[item][page] .title .message
    out: Vec<Vec<Page<T, M>>>,
}

impl<V, const T: usize, const M: usize> MockDriver<V, T, M> {
    pub fn new(viewable: V) -> Self {
        Self {
            viewable: Box::new(viewable),
            print: true,
            out: Default::default(),
        }
    }

    pub fn out_ui(&self) -> &[Vec<Page<T, M>>] {
        self.out.as_slice()
    }

    pub fn with_print(&mut self, print: bool) {
        self.print = print
    }
}

impl<V: Viewable, const T: usize, const M: usize> MockDriver<V, T, M> {
    /// This function allows `callback` to be invoked for each page of each item
    /// that the inner `Viewable` has to offer
    ///
    /// It will also `drive` if there's no data to pass to the callback
    ///
    /// The callback is passed 4 arguments: the item id, the page number, the title and the message
    pub fn verify_with<F, E>(&mut self, mut callback: F) -> Result<(), Vec<E>>
    where
        F: FnMut(usize, usize, &[u8; T], &[u8; M]) -> Result<(), E>,
    {
        if self.out.is_empty() {
            self.drive();
        }

        let mut errors = vec![];
        for (i, item) in self.out.iter().enumerate() {
            for (j, page) in item.iter().enumerate() {
                if let Err(e) = callback(i, j, &page.title, &page.message) {
                    errors.push(e)
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// This function will go thru each page of each item and collect
    /// all the outputs of the viewable
    pub fn drive(&mut self) {
        let num_items = self
            .viewable
            .num_items()
            .expect("unable to retrieve num_items");

        //render each item
        for item_n in 0..num_items {
            //create new containers for this item's pages
            self.out.push(Vec::new());
            let pages = self.out.last_mut().unwrap();

            let mut page_n = 0;
            //set an initial max_page to 255 to make sure we get at least 1 page
            let mut max_pages = 255;

            //render each page of an item
            while page_n < max_pages {
                let mut page = Page::default();

                max_pages = self
                    .viewable
                    .render_item(item_n, &mut page.title[..], &mut page.message[..], page_n)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Error when rendering item #{}, page #{}/#{}; err: {:?}",
                            item_n, page_n, max_pages, e
                        )
                    });

                if self.print {
                    let title = std::str::from_utf8(&page.title[..]).unwrap_or_else(|e| {
                        panic!(
                            "title was not UTF-8; item #{}, page #{}/#{}; err : {:?}",
                            item_n, page_n, max_pages, e
                        )
                    });
                    let message = std::str::from_utf8(&page.message[..]).unwrap_or_else(|e| {
                        panic!(
                            "message was not UTF-8; item #{}, page #{}/#{}; err : {:?}",
                            item_n, page_n, max_pages, e
                        )
                    });

                    println!("{} | {} : {}", item_n, title, message)
                }

                //store page
                pages.push(page);

                //increase counter for next page
                page_n += 1;
            }
        }
    }

    pub fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        self.viewable.accept(out)
    }

    pub fn reject(&mut self, out: &mut [u8]) -> (usize, u16) {
        self.viewable.reject(out)
    }
}

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
    data: std::vec::Vec<T>,
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

pub fn handle_ui_message(item: &[u8], out: &mut [u8], page: u8) -> Result<u8, ParserError> {
    let m_len = out.len() - 1; //null byte terminator
    if m_len < 1 {
        return Err(ParserError::UnexpectedBufferEnd);
    }
    if m_len <= item.len() {
        let chunk = item
            .chunks(m_len) //divide in non-overlapping chunks
            .nth(page as usize) //get the nth chunk
            .ok_or(ParserError::UnexpectedValue)?;

        out[..chunk.len()].copy_from_slice(chunk);
        out[chunk.len()] = 0; //null terminate

        let n_pages = item.len() / m_len;
        Ok(1 + n_pages as u8)
    } else {
        out[..item.len()].copy_from_slice(item);
        out[item.len()] = 0; //null terminate
        Ok(1)
    }
}

pub fn strlen(s: &[u8]) -> usize {
    let mut count = 0;
    while let Some(&c) = s.get(count) {
        if c == 0 {
            return count;
        }
        count += 1;
    }

    panic!("byte slice did not terminate with null byte, s: {:x?}", s)
}
