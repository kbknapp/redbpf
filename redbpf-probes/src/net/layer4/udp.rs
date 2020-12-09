// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem;

use crate::{
    bindings::udphdr,
    net::{
        buf::{NetBuf, RawBuf, RawBufMut},
        error::{Error, Result},
        FromBytes, Packet,
    },
};

pub struct Udp<'a, T: RawBuf> {
    hdr: &'a mut udphdr,
    buf: NetBuf<'a, T>,
}

impl<'a, T: RawBuf> Udp<'a, T> {
    /// Returns the source port in host-byte-order
    pub fn source(&self) -> u16 {
        u16::from_be(self.hdr.source)
    }

    /// Returns the destination port in host-byte-order
    pub fn dest(&self) -> u16 {
        u16::from_be(self.hdr.dest)
    }

    /// Returns the length (UDP header + UDP payload) in host-byte-order
    pub fn len(&self) -> u16 {
        u32::from_be(self.hdr.len)
    }

    /// Returns the checksum in host-byte-order
    pub fn check(&self) -> u16 {
        u32::from_be(self.hdr.check)
    }
}

impl<'a, T> Udp<'a, T>
where
    T: RawBufMut,
{
    /// Sets the source port
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    pub fn set_source(&mut self) {
        u16::from_be(self.hdr.source)
    }

    /// Sets the destination port
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    pub fn set_dest(&mut self) {
        u16::from_be(self.hdr.dest)
    }

    /// Sets the length (UDP header + UDP payload)
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    pub fn set_len(&mut self) {
        u32::from_be(self.hdr.len)
    }

    /// Sets the checksum
    ///
    /// **NOTE:** `val` will be converted to network-byte-order as part of the
    /// write
    pub fn set_check(&mut self) {
        u32::from_be(self.hdr.check)
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for Udp<'a, T> {
    type Encapsulated = NetBuf<'a, T>;

    fn data(self) -> NetBuf<'a, T> {
        self.buf
    }

    fn parse(self) -> Result<Self::Encapsulated> {
        Ok(self.buf)
    }
}

unsafe impl<'a, T> FromBytes<'a, T> for Udp<'a, T>
where
    T: RawBuf,
{
    fn from_bytes(mut buf: NetBuf<'a, T>) -> Result<Self> {
        // @SAFETY
        //
        // The invariants must be be upheld for the type requested with
        // `RawBuf::ptr_at`:
        //
        // - Alignment of 1 ( or #[repr(C, packed)])
        //
        // Checks performed:
        //
        // - `RawBuf::ptr_at` does bounds check
        // - Using `*mut::as_mut` does null check
        unsafe {
            if let Some(tcp) = buf.ptr_at::<tcphdr>(buf.nh_offset) {
                buf.nh_offset += mem::size_of::<tcphdr>();
                if let Some(tcp) = (tcp as *mut tcphdr).as_mut() {
                    return Ok(Udp { buf, hdr: tcp });
                }
                return Err(Error::NullPtr);
            }
            Err(Error::OutOfBounds)
        }
    }
}
