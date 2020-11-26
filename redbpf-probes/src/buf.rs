// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// Represents a raw Buffer ("raw" meaning it works with, and gives out raw
/// pointers) such as that pointed to by [`XdpContext`]. This trait is meant to
/// be a low level building block for higher level abstractions.
///
/// [`XdpContext`]: crate::xdp::XdpContext
pub trait RawBuf
{
    /// Returns the start address of the buffer
    fn start(&self) -> usize;
    /// Returns the end address of the buffer
    fn end(&self) -> usize;

    /// Returns the buffer length.
    #[inline]
    fn len(&self) -> usize {
        self.data_end() - self.data_start()
    }

    /// Returns a raw pointer to a given address inside the buffer.
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
    unsafe fn ptr_at<U>(&self, addr: usize) -> Option<*const U> {
        if self.check_bounds(addr, addr + mem::size_of::<U>()) {
            return Some(addr as *const U)
        }
        None
    }

    /// Returns a raw mutable pointer to a given address inside the buffer.
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
    unsafe fn ptr_at_mut<U>(&self, addr: usize) -> Option<*mut U> {
        if self.check_bounds(addr, addr + mem::size_of::<U>())? {
            return Some(addr as *mut U);
        }
        None
    }

    /// Returns a raw pointer to the address following `prev` plus the size of a `T`
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
    unsafe fn ptr_after<T, U>(&self, prev: *const T) -> Option<*const U> {
        self.ptr_at(prev as usize + mem::size_of::<T>())
    }

    /// Returns a raw mutable pointer to the address following `prev` plus the size of a `T`
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
    unsafe fn ptr_after<T, U>(&self, prev: *const T) -> Option<*mut U> {
        self.ptr_at(prev as usize + mem::size_of::<T>())
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

    /// Returns this buffer as a raw pointer
    #[inline]
    fn as_ptr(&self, addr: usize) -> *const u8 {
        self.start() as *const u8
    }

    /// Returns this buffer as a raw pointer
    #[inline]
    fn as_ptr_mut(&self, addr: usize) -> *mut u8 {
        self.start() as *mut u8
    }

    /// Returns a raw pointer to the address of `self.start() + offset` ensuring
    /// the remaining space is enough to point to a `T`
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
    unsafe fn offset<T>(&self, offset: usize) -> Option<*const T> {
        self.ptr_at(self.start() + offset)
    }

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
    unsafe fn offset<T>(&self, offset: usize) -> Option<*mut T> {
        self.ptr_at_mut(self.start() + offset)
    }

    /// Returns a `slice` of `len` bytes starting at `offset` from the buffer
    #[inline]
    pub fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        unsafe {
            let start = self.start() + offset;
            self.check_bounds(start, start + len)?;
            let s = slice::from_raw_parts(self.as_ptr(), len);
            Some(s)
        }
    }

    /// Returns the buffer as a `slice` of bytes
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.slice(0, self.len()).unwrap()
    }
}
