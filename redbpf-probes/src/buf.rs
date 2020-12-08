// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::{mem, slice};

/// Represents a raw Buffer ("raw" meaning it works with, and gives out raw
/// pointers) such as that pointed to by [`XdpContext`]. This trait is meant to
/// be a low level building block for higher level abstractions.
///
/// The only required methods are `RawBuf::start` and `RawBuf::end` which return
/// an address to the start and and end of the buffer.
///
/// If one does not have an end address, you can re-implement `RawBuf::len` and
/// simply add it to `RawBuf::start`
///
/// [`XdpContext`]: crate::xdp::XdpContext
pub trait RawBuf {
    /// Returns the start address of the buffer
    fn start(&self) -> usize;

    /// Returns the end address of the buffer
    fn end(&self) -> usize;

    /// Returns the buffer byte length.
    #[inline]
    fn len(&self) -> usize {
        self.end() - self.start()
    }

    /// Returns a raw pointer to the address of `self.start() + offset` ensuring
    /// the remaining space is enough to point to a `T`
    ///
    /// # Safety
    ///
    /// This method uses [`RawBuf::check_bounds`] to ensure the given address
    /// `offset` is within the buffer and allows enough following space to point
    /// to something of type `U`. However no checks are done to ensure the
    /// returned pointer points to a valid bit pattern of type `U`, nor are any
    /// alignments checked. Ensuring proper alignment is followed and that the
    /// pointed to address is a valid bit pattern of type `U` is left up to the
    /// caller.
    ///
    /// [`RawBuf::check_bounds`]: crate::RawBuf::check_bounds
    #[inline]
    unsafe fn ptr_at<U>(&self, offset: usize) -> Option<*const U> {
        if self.check_bound(offset + mem::size_of::<U>()) {
            return Some(offset as *const U);
        }
        None
    }

    /// Returns a raw pointer to the address following `prev` plus the size of a `T`
    ///
    /// # Safety
    ///
    /// This method uses [`RawBuf::check_bounds`] to ensure the given pointer
    /// address `prev` is within the buffer and allows enough following space to
    /// point to something of type `U`. However no checks are done to ensure the
    /// returned pointer points to a valid bit pattern of type `U`, nor are any
    /// alignments checked. Ensuring proper alignment is followed and that the
    /// pointed to address is a valid bit pattern of type `U` is left up to the
    /// caller.
    ///
    /// [`RawBuf::check_bounds`]: crate::RawBuf::check_bounds
    #[inline]
    unsafe fn ptr_after<T, U>(&self, prev: *const T) -> Option<*const U> {
        if self.check_bounds(prev as usize, prev as usize + mem::size_of::<T>()) {
            return self.ptr_at((prev as usize - self.start()) + mem::size_of::<T>());
        }
        None
    }

    /// Ensures that addresses `start` and `end` are within this buffer.
    #[inline]
    fn check_bounds(&self, start: usize, end: usize) -> bool {
        !(start >= end || start < self.start() || end > self.end())
    }

    /// Ensures that addresses `addr` is within this buffer.
    #[inline]
    fn check_bound(&self, addr: usize) -> bool {
        !(addr > self.end() || addr < self.start())
    }

    /// Returns a `slice` of `len` bytes starting at `offset` from the buffer
    #[inline]
    fn slice_at(&self, offset: usize, len: usize) -> Option<&[u8]> {
        unsafe {
            let start = self.start() + offset;
            if self.check_bounds(start, start + len) {
                let s = slice::from_raw_parts(self.ptr_at(0)?, len);
                return Some(s);
            }
            None
        }
    }

    /// Returns the buffer as a `slice` of bytes
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.slice_at(0, self.len()).unwrap()
    }
}

/// Represents a raw mutable Buffer ("raw" meaning it works with, and gives out
/// raw mutable pointers) such as that pointed to by [`XdpContext`]. This trait
/// is meant to be a low level building block for higher level abstractions.
///
/// [`XdpContext`]: crate::xdp::XdpContext
pub trait RawBufMut: RawBuf {
    /// Returns a raw mutable pointer to the address of `self.start() + offset`
    /// ensuring the remaining space is enough to point to a `T`
    ///
    /// # Safety
    ///
    /// This method uses [`RawBuf::check_bounds`] to ensure the given address
    /// `addr` is within the buffer and allows enough following space to point
    /// to something of type `U`. However no checks are done to ensure the
    /// returned pointer points to a valid bit pattern of type `U`, nor are any
    /// alignments checked. Ensuring proper alignment is followed and pointed to
    /// address is a valid bit pattern of type `U` is left up to the caller.
    ///
    /// [`RawBuf::check_bounds`]: crate::RawBuf::check_bounds
    #[inline]
    unsafe fn ptr_at_mut<T>(&self, offset: usize) -> Option<*mut T> {
        self.ptr_at_mut(self.start() + offset)
    }

    /// Returns a raw mutable pointer to the address following `prev` plus the size of a `T`
    ///
    /// # Safety
    ///
    /// This method uses [`RawBuf::check_bounds`] to ensure the given pointer
    /// address `prev` is within the buffer and allows enough following space to
    /// point to something of type `U`. However no checks are done to ensure the
    /// returned pointer points to a valid bit pattern of type `U`, nor are any
    /// alignments checked. Ensuring proper alignment is followed and that the
    /// pointed to address is a valid bit pattern of type `U` is left up to the
    /// caller.
    ///
    /// [`RawBuf::check_bounds`]: crate::RawBuf::check_bounds
    #[inline]
    unsafe fn ptr_after_mut<T, U>(&self, prev: *const T) -> Option<*mut U> {
        self.ptr_at_mut(prev as usize + mem::size_of::<T>())
    }

    /// Returns a mutable `slice` of `len` bytes starting at `offset` from the
    /// buffer
    #[inline]
    fn slice_at_mut(&self, offset: usize, len: usize) -> Option<&mut [u8]> {
        unsafe {
            let start = self.start() + offset;
            if self.check_bounds(start, start + len) {
                let s = slice::from_raw_parts_mut(self.ptr_at_mut(0)?, len);
                return Some(s);
            }
            None
        }
    }

    /// Returns the buffer as a mutable `slice` of bytes
    #[inline]
    fn as_slice_mut(&self) -> &mut [u8] {
        self.slice_at_mut(0, self.len()).unwrap()
    }
}
