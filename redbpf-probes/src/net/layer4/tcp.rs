// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem;

use crate::{
    bindings::tcphdr,
    net::{
        buf::{NetBuf, RawBuf, RawBufMut},
        error::{Error, Result},
        FromBytes, Packet,
    },
};

pub struct Tcp<'a, T: RawBuf> {
    hdr: &'a mut tcphdr,
    buf: NetBuf<'a, T>,
}

impl<'a, T: RawBuf> Tcp<'a, T> {
    /// Returns the source port (LE)
    pub fn source(&self) -> u16 {
        unimplemented!()
    }

    /// Returns the destination port (LE)
    pub fn dest(&self) -> u16 {
        unimplemented!()
    }

    /// Returns the sequence number (LE)
    pub fn seq(&self) -> u32 {
        unimplemented!()
    }

    /// Returns the ACK (acknowledgement) number (LE)
    pub fn ack_seq(&self) -> u32 {
        unimplemented!()
    }

    /// Returns the data offset in bytes
    #[inline]
    pub fn doff(&self) -> u8 {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(4usize, 4u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn res1(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(0usize, 4u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn fin(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(8usize, 1u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn syn(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(9usize, 1u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn rst(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(10usize, 1u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn psh(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(11usize, 1u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn ack(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(12usize, 1u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn urg(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(13usize, 1u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn ece(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(14usize, 1u8) as u16) }
        unimplemented!()
    }

    #[inline]
    pub fn cwr(&self) -> bool {
        //unsafe { ::core::mem::transmute(self.hdr._bitfield_1.get(15usize, 1u8) as u16) }
        unimplemented!()
    }
}

// @TODO set_* methods
impl<'a, T> Tcp<'a, T>
where
    T: RawBufMut,
{
    #[inline]
    pub fn set_doff(&mut self, val: u8) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(4usize, 4u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_res1(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(0usize, 4u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_fin(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(8usize, 1u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_syn(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(9usize, 1u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_rst(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(10usize, 1u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_psh(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(11usize, 1u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_ack(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(12usize, 1u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_urg(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(13usize, 1u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_ece(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(14usize, 1u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn set_cwr(&mut self, val: bool) {
        // unsafe {
        //     let val: u16 = ::core::mem::transmute(val);
        //     self.hdr._bitfield_1.set(15usize, 1u8, val as u64)
        // }
        unimplemented!()
    }

    #[inline]
    pub fn new_flags(
        &mut self,
        res1: u16,
        doff: u16,
        fin: u16,
        syn: u16,
        rst: u16,
        psh: u16,
        ack: u16,
        urg: u16,
        ece: u16,
        cwr: u16,
    ) {
        // let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 2usize], u8> =
        //     Default::default();
        // __bindgen_bitfield_unit.set(0usize, 4u8, {
        //     let res1: u16 = unsafe { ::core::mem::transmute(res1) };
        //     res1 as u64
        // });
        // __bindgen_bitfield_unit.set(4usize, 4u8, {
        //     let doff: u16 = unsafe { ::core::mem::transmute(doff) };
        //     doff as u64
        // });
        // __bindgen_bitfield_unit.set(8usize, 1u8, {
        //     let fin: u16 = unsafe { ::core::mem::transmute(fin) };
        //     fin as u64
        // });
        // __bindgen_bitfield_unit.set(9usize, 1u8, {
        //     let syn: u16 = unsafe { ::core::mem::transmute(syn) };
        //     syn as u64
        // });
        // __bindgen_bitfield_unit.set(10usize, 1u8, {
        //     let rst: u16 = unsafe { ::core::mem::transmute(rst) };
        //     rst as u64
        // });
        // __bindgen_bitfield_unit.set(11usize, 1u8, {
        //     let psh: u16 = unsafe { ::core::mem::transmute(psh) };
        //     psh as u64
        // });
        // __bindgen_bitfield_unit.set(12usize, 1u8, {
        //     let ack: u16 = unsafe { ::core::mem::transmute(ack) };
        //     ack as u64
        // });
        // __bindgen_bitfield_unit.set(13usize, 1u8, {
        //     let urg: u16 = unsafe { ::core::mem::transmute(urg) };
        //     urg as u64
        // });
        // __bindgen_bitfield_unit.set(14usize, 1u8, {
        //     let ece: u16 = unsafe { ::core::mem::transmute(ece) };
        //     ece as u64
        // });
        // __bindgen_bitfield_unit.set(15usize, 1u8, {
        //     let cwr: u16 = unsafe { ::core::mem::transmute(cwr) };
        //     cwr as u64
        // });
        // __bindgen_bitfield_unit
        todo!("impl Tcp::new_flags")
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for Tcp<'a, T> {
    type Encapsulated = NetBuf<'a, T>;

    fn data(self) -> NetBuf<'a, T> {
        self.buf
    }

    fn parse(self) -> Result<Self::Encapsulated> {
        Ok(self.buf)
    }
}

unsafe impl<'a, T> FromBytes<'a, T> for Tcp<'a, T>
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
                    return Ok(Tcp { buf, hdr: tcp });
                }
                return Err(Error::NullPtr)
            }
            Err(Error::OutOfBounds)
        }
    }
}
