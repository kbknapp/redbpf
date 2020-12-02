// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

pub struct Ethernet<'a, T> {
    buf: DataBuf<'a, T>,
    hdr: &mut ethhdr,
}

impl<'a, T> Ethernet<'a, T> {
    /// Returns the Source MAC address
    pub fn source(&self) -> &[u8; 6] {
        &self.inner.h_source
    }
    /// Returns the Destination MAC address
    pub fn dest(&self) -> &[u8; 6] {
        &self.inner.h_dest
    }

    // @TODO Use an enum?
    /// Returns protocol in BE
    pub fn proto(&self) -> u16 {
        u16::from_be(self.inner.h_proto)
    }
}

// @TODO set_* methods
impl<'a, T> Ethernet<'a, T> where T: RawBufMut {
    /// Returns the Source MAC address
    pub fn source_mut(&self) -> &mut [u8; 6] {
        &mut self.inner.h_source
    }
    /// Returns the Destination MAC address
    pub fn dest_mut(&self) -> &mut [u8; 6] {
        &mut self.inner.h_dest
    }

    // @TODO Use an enum?
    /// Returns protocol in LE
    pub fn proto_mut(&self) -> &mut u16 {
        &mut self.inner.h_proto
    }
}

impl<'a, T: RawBuf> Packet for Ethernet<'a, T> {}
impl<'a, T: RawBufMut> PacketMut for Ethernet<'a, T> {}

unsafe impl<'a, T> FromBytes for Ethernet<'a, T> {
    fn from_bytes(buf: mut DataBuf<'a, T>) -> Result<Self> {
        if let Some(eth) = buf.buf.ptr_at::<ethhdr>(buf.hdr_offset)?.as_mut() {
            buf.nh_offset += mem::size_of::<ethhdr>();
            Ethernet {
                buf: buf,
                hdr: eth,
            }
        }

        Err(Error::TypeFromBytes)
    }
}
