// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// Represents a raw Network Buffer such as that pointed to by [`XdpContext`].
/// This trait is meant to be a low level building block for higher level
/// abstractions such as network packets and protocol types.
///
/// [`XdpContext`]: crate::xdp::XdpContext
pub trait Buf
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
    /// This method uses [`Buf::check_bounds`] to ensure the given address in
    /// `addr` is within the buffer and allows enough following space for
    /// something of type `U`. However no checks are done to ensure the returned
    /// pointer actually points to a valid `U`, nor are any alignments checked.
    /// Ensuring proper alignment is followed and pointed to address is a valid
    /// bit pattern of type `U` is left up to the caller.
    ///
    /// [`Buf::check_bounds`]: crate::net::Buf::check_bounds
    #[inline]
    unsafe fn ptr_at<U>(&self, addr: usize) -> Result<*const U> {
        self.check_bounds(addr, addr + mem::size_of::<U>())?;

        Ok(addr as *const U)
    }

    /// Returns a raw mutable pointer to a given address inside the buffer.
    ///
    /// # Safety
    ///
    /// This method uses `Buf::check_bounds` to ensure the given address in
    /// `addr` is within the buffer and allows enough following space for
    /// something of type `U`. However no checks are done to ensure the returned
    /// pointer actually points to a valid `U`, nor are any alignments checked.
    /// Ensuring proper alignment is followed and pointed to address is a valid
    /// bit pattern of type `U` is left up to the caller.
    ///
    /// [`Buf::check_bounds`]: crate::net::Buf::check_bounds
    #[inline]
    unsafe fn ptr_at_mut<U>(&self, addr: usize) -> Result<*mut U> {
        self.check_bounds(addr, addr + mem::size_of::<U>())?;

        Ok(addr as *mut U)
    }

    /// Returns a raw pointer to the address following `prev` plus the size of a `T`
    ///
    /// # Safety
    ///
    /// This method uses `Buf::check_bounds` to ensure the given address in
    /// `addr` is within the buffer and allows enough following space for
    /// something of type `U`. However no checks are done to ensure the returned
    /// pointer actually points to a valid `U`, nor are any alignments checked.
    /// Ensuring proper alignment is followed and pointed to address is a valid
    /// bit pattern of type `U` is left up to the caller.
    ///
    /// [`Buf::check_bounds`]: crate::net::Buf::check_bounds
    #[inline]
    unsafe fn ptr_after<T, U>(&self, prev: *const T) -> Result<*const U> {
        self.ptr_at(prev as usize + mem::size_of::<T>())
    }

    /// Returns a raw mutable pointer to the address following `prev` plus the size of a `T`
    ///
    /// # Safety
    ///
    /// This method uses `Buf::check_bounds` to ensure the given address in
    /// `addr` is within the buffer and allows enough following space for
    /// something of type `U`. However no checks are done to ensure the returned
    /// pointer actually points to a valid `U`, nor are any alignments checked.
    /// Ensuring proper alignment is followed and pointed to address is a valid
    /// bit pattern of type `U` is left up to the caller.
    ///
    /// [`Buf::check_bounds`]: crate::net::Buf::check_bounds
    #[inline]
    unsafe fn ptr_after<T, U>(&self, prev: *const T) -> Result<*mut U> {
        self.ptr_at(prev as usize + mem::size_of::<T>())
    }

    /// Ensures that addresses `start` and `end` are within this buffer.
    #[inline]
    fn check_bounds(&self, start: usize, end: usize) -> Result<()> {
        if start >= end || start < self.start() || end > self.end() {
            return Err(Error::OutOfBounds);
        }

        Ok(())
    }
}
