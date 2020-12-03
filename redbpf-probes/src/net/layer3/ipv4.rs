// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem;

use crate::{
    bindings::iphdr,
    buf::{RawBuf, RawBufMut},
    net::{error::Error, DataBuf, FromBytes, Packet},
};

pub struct Ipv4<'a, T> {
    buf: DataBuf<'a, T>,
    hdr: &'a mut iphdr,
}

impl<'a, T> Ipv4<'a, T> {
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
        unimplemented!()
    }

    /// Returns the TOS (Type of Service) as a byte
    pub fn tos(&self) -> u8 {
        unimplemented!()
    }

    /// Returns the total length of the packet in bytes (LE), including the
    /// header + body
    pub fn tot_len(&self) -> u16 {
        unimplemented!()
    }

    /// Returns the segment ID (in LE)
    pub fn id(&self) -> u16 {
        unimplemented!()
    }

    /// Returns the fragmentaiton flags bitfield where:
    ///
    /// ```
    ///    /-- Reserved (must be zero)
    ///   //-- Don't Fragment
    ///  ///-- More Fragments
    /// 000
    /// ```
    ///
    /// This bitfield is converted from a BE u16 and returned as a byte value where:
    ///
    /// ```
    /// 0 = No fragements
    /// 2 = Don't Fragement
    /// 4 = More Fragements
    /// ```
    pub fn flags(&self) -> u8 {
        unimplemented!()
    }

    /// Returns the fragmentation offset (BE)
    pub fn frag_off(&self) -> u16 {
        unimplemented!()
    }

    /// Returns the TTL (Time to Live)
    pub fn ttl(&self) -> u8 {
        unimplemented!()
    }

    /// Returns the protocol used in the body
    pub fn protocol(&self) -> u8 {
        unimplemented!()
    }

    /// Returns the header checksum (LE)
    pub fn check(&self) -> u16 {
        unimplemented!()
    }

    /// Returns the source IPv4 Address (LE)
    pub fn sadder(&self) -> u32 {
        unimplemented!()
    }

    /// Returns the destination IPv4 Address (LE)
    pub fn dadder(&self) -> u32 {
        unimplemented!()
    }
}

// @TODO set_* methods
impl<'a, T> Ipv4<'a, T>
where
    T: RawBufMut,
{
    /// Returns the version of the header
    pub fn version_mut(&mut self) -> &mut u8 {
        unimplemented!()
    }

    /// Returns the IHL (Internet Header Length) in bytes
    ///
    /// The raw value is a 4 bit number which represents the number of 32 bit
    /// words in the header. There is a minimum value of 5, which coresponds to
    /// 20 bytes (5x32=160bits=20bytes), and a maximum value of 15, or 60 bytes
    /// (15x32=480bits=60bytes)
    pub fn ihl_mut(&mut self) -> &mut u8 {
        unimplemented!()
    }

    /// Returns the TOS (Type of Service) as a byte
    pub fn tos_mut(&mut self) -> &mut u8 {
        unimplemented!()
    }

    /// Returns the total length of the packet in bytes (LE), including the
    /// header + body
    pub fn tot_len_mut(&mut self) -> &mut u16 {
        unimplemented!()
    }

    /// Returns the segment ID (in LE)
    pub fn id_mut(&mut self) -> &mut u16 {
        unimplemented!()
    }

    /// Returns the fragmentaiton flags bitfield where:
    ///
    /// ```
    ///    /-- Reserved (must be zero)
    ///   //-- Don't Fragment
    ///  ///-- More Fragments
    /// 000
    /// ```
    ///
    /// This bitfield is converted from a BE u16 and returned as a byte value where:
    ///
    /// ```
    /// 0 = No fragements
    /// 2 = Don't Fragement
    /// 4 = More Fragements
    /// ```
    pub fn flags_mut(&mut self) -> &mut u8 {
        unimplemented!()
    }

    /// Returns the fragmentation offset (BE)
    pub fn frag_off_mut(&mut self) -> &mut u16 {
        unimplemented!()
    }

    /// Returns the TTL (Time to Live)
    pub fn ttl_mut(&mut self) -> &mut u8 {
        unimplemented!()
    }

    /// Returns the protocol used in the body
    pub fn protocol_mut(&mut self) -> &mut u8 {
        unimplemented!()
    }

    /// Returns the header checksum (LE)
    pub fn check_mut(&mut self) -> &mut u16 {
        unimplemented!()
    }

    /// Returns the source IPv4 Address (LE)
    pub fn sadder_mut(&mut self) -> &mut u32 {
        unimplemented!()
    }

    /// Returns the destination IPv4 Address (LE)
    pub fn dadder_mut(&mut self) -> &mut u32 {
        unimplemented!()
    }
}

impl<'a, T: RawBuf> Packet for Ipv4<'a, T> {
    fn buf(self) -> DataBuf<'a, T> {
        self.buf
    }
}

unsafe impl<'a, T> FromBytes for Ipv4<'a, T> {
    fn from_bytes(mut buf: DataBuf<'a, T>) -> Result<Self> {
        if let Some(ip) = buf.ptr_at::<iphdr>(buf.nh_offset)?.as_mut() {
            buf.nh_offset += mem::size_of::<iphdr>();
            Ipv4 { buf, hdr: ip }
        }

        Err(Error::TypeFromBytes)
    }
}
