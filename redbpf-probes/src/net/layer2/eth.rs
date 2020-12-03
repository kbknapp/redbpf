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
    /// Returns protocol in host byte order
    pub fn proto(&self) -> u16 {
        u16::from_be(self.inner.h_proto)
    }
}

impl<'a, T> Ethernet<'a, T> where T: RawBufMut {
    /// Sets the source MAC address.
    pub fn set_source(&mut self, val: &[u8; 6]) {
        todo!("impl Ethernet::set_source")
    }

    /// Sets the Destination MAC address
    pub fn set_dest(&mut self, val: &[u8; 6]) {
        todo!("impl Ethernet::set_dest")
    }

    /// Sets the protocol.
    ///
    /// **NOTE:** `val` will be converted to network byte order (BE) as part of
    /// the write process.
    pub fn set_proto(&self, val: &u16) {
        todo!("impl Ethernet::set_proto")
    }
}

impl<'a, T: RawBuf> Packet for Ethernet<'a, T> {
    type Encapsulated = L3Proto;

    fn buf(self) -> DataBuf<'a, T> {
        self.buf
    }

    fn parse_from(self) -> Result<Self::Encapsulated> {
        match self.proto() {
            ETH_P_IP => Ok(L3Proto::Ipv4(self.parse::<Ipv4>()?)),
            _ => Err(Error::UnknownProtocol)
        }
    }
}

unsafe impl<'a, T> FromBytes for Ethernet<'a, T> {
    fn from_bytes(buf: mut DataBuf<'a, T>) -> Result<Self> {
        if let Some(eth) = buf.ptr_at::<ethhdr>(buf.nh_offset)?.as_mut() {
            buf.nh_offset += mem::size_of::<ethhdr>();
            Ethernet {
                buf: buf,
                hdr: eth,
            }
        }

        Err(Error::TypeFromBytes)
    }
}
