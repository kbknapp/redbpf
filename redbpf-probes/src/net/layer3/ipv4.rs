// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem;

use crate::{
    bindings::{iphdr, IPPROTO_TCP},
    net::{
        buf::{NetBuf, RawBuf, RawBufMut},
        error::{Error, Result},
        layer4::{L4Proto, Tcp},
        FromBytes, Packet,
    },
};

pub struct Ipv4<'a, T: RawBuf> {
    hdr: &'a mut iphdr,
    buf: NetBuf<'a, T>,
}

impl<'a, T: RawBuf> Ipv4<'a, T> {
    /// Returns the version of the header
    pub fn version(&self) -> u8 {
        4
    }

    /// Returns the IHL (Internet Header Length) in bytes
    ///
    /// The raw value is a 4 bit number which represents the number of 32 bit
    /// words in the header. There is a minimum value of 5, which coresponds to
    /// 20 bytes (5x32=160bits=20bytes), and a maximum value of 15, or 60 bytes
    /// (15x32=480bits=60bytes)
    pub fn ihl(&self) -> u8 {
        self.hdr.ihl()
    }

    /// Returns the TOS (Type of Service) as a byte
    pub fn tos(&self) -> u8 {
        self.hdr.tos
    }

    /// Returns the total length of the packet in bytes (in host-byte-order),
    /// including the header + body
    pub fn tot_len(&self) -> u16 {
        u16::from_be(self.hdr.tot_len)
    }

    /// Returns the segment ID (in host-byte-order)
    pub fn id(&self) -> u16 {
        u16::from_be(self.hdr.id)
    }

    /// Returns `true` if the DF (Don't Fragment) bit is set
    pub fn df(&self) -> bool {
        self.hdr.frag_off & 0x4000 == 1
    }

    /// Returns `true` if the MF (More Fragments) bit is set
    pub fn mf(&self) -> bool {
        self.hdr.frag_off & 0x2000 == 1
    }

    /// Returns the TTL (Time to Live)
    pub fn ttl(&self) -> u8 {
        self.hdr.ttl
    }

    /// Returns the protocol used in the body
    pub fn protocol(&self) -> u8 {
        self.hdr.protocol
    }

    /// Returns the header checksum
    pub fn check(&self) -> u16 {
        self.hdr.check
    }

    /// Returns the source IPv4 Address (in host-byte-order)
    pub fn sadder(&self) -> u32 {
        u32::from_be(self.hdr.saddr)
    }

    /// Returns the destination IPv4 Address (in host-byte-order)
    pub fn dadder(&self) -> u32 {
        u32::from_be(self.hdr.daddr)
    }
}

impl<'a, T> Ipv4<'a, T>
where
    T: RawBufMut,
{
    /// Sets the version of the header
    pub fn set_version(&mut self, val: u8) {
        self.hdr.set_version(val);
    }

    /// Sets the IHL (Internet Header Length) in bytes
    pub fn set_ihl(&mut self, val: u8) {
        self.hdr.set_ihl(val);
    }

    /// Sets the TOS (Type of Service)
    pub fn set_tos(&mut self, val: u8) {
        self.hdr.tos = val;
    }

    /// Sets the total length of the packet in bytes, including the
    /// header + body
    ///
    /// **NOTE:** The value will be converted from host-byte-order to
    /// network-byte-order as part of the write.
    pub fn set_tot_len(&mut self, val: u16) {
        self.hdr.tot_len = u16::to_be(val);
    }

    /// Sets the segment ID
    ///
    /// **NOTE:** The value will be converted from host-byte-order to
    /// network-byte-order as part of the write.
    pub fn set_id(&mut self, val: u16) {
        self.hdr.id = u16::to_be(val);
    }

    /// Sets the DF flag (Don't Fragment)
    pub fn set_df(&mut self) {
        self.hdr.frag_off |= 0x4000;
    }

    /// Sets/unsets the DF flag (Don't Fragment)
    pub fn toggle_df(&mut self) {
        self.hdr.frag_off ^= 0x4000;
    }

    /// Sets the MF flag (More Fragments)
    pub fn set_mf(&mut self) {
        self.hdr.frag_off |= 0x2000;
    }

    /// Sets/unsets the MF flag (More Fragments)
    pub fn toggle_mf(&mut self) {
        self.hdr.frag_off ^= 0x2000;
    }

    /// Sets the TTL (Time to Live)
    pub fn set_ttl(&mut self, val: u8) {
        self.hdr.ttl = val;
    }

    /// Decrements the TTL (Time to Live) by one (1)
    pub fn decr_ttl(&mut self) {
        self.hdr.ttl -= 1;
    }

    /// Increments the TTL (Time to Live) by one (1)
    pub fn incr_ttl(&mut self) {
        self.hdr.ttl += 1;
    }

    /// Sets the protocol used in the body
    pub fn set_protocol(&mut self, val: u8) {
        self.hdr.protocol = val;
    }

    /// Sets the header checksum
    ///
    /// **NOTE:** The value will be converted from host-byte-order to
    /// network-byte-order as part of the write.
    pub fn set_check(&mut self, val: u16) {
        self.hdr.check = u16::to_be(val);
    }

    /// Sets the source IPv4 Address
    ///
    /// **NOTE:** The value will be converted from host-byte-order to
    /// network-byte-order as part of the write.
    pub fn sadder_mut(&mut self, val: u32) {
        self.hdr.saddr = u32::to_be(val);
    }

    /// Sets the destination IPv4 Address
    ///
    /// **NOTE:** The value will be converted from host-byte-order to
    /// network-byte-order as part of the write.
    pub fn dadder_mut(&mut self, val: u32) {
        self.hdr.daddr = u32::to_be(val);
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for Ipv4<'a, T> {
    type Encapsulated = L4Proto<'a, T>;

    fn data(self) -> NetBuf<'a, T> {
        self.buf
    }

    fn parse(self) -> Result<Self::Encapsulated> {
        match self.protocol() {
            p if p as u32 == IPPROTO_TCP => {
                return Ok(L4Proto::Tcp(Tcp::from_bytes(self.data())?));
            }
            p => return Err(Error::UnimplementedProtocol(p as u32)),
        }
    }
}

unsafe impl<'a, T> FromBytes<'a, T> for Ipv4<'a, T>
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
            if let Some(ip) = buf.ptr_at::<iphdr>(buf.nh_offset) {
                buf.nh_offset += mem::size_of::<iphdr>();
                if let Some(ip) = (ip as *mut iphdr).as_mut() {
                    return Ok(Ipv4 { buf, hdr: ip });
                }
                return Err(Error::NullPtr)
            }
            Err(Error::OutOfBounds)
        }
    }
}
