// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Types and traits for working with networking data.

The main trait exported by this module is `NetworkBuffer`. It's implemented
by
[`XdpContext`](https://ingraind.org/api/redbpf_probes/xdp/struct.XdpContext.html)
to provide access to the network data.
 */
use crate::bindings::*;
use core::mem;
use core::slice;
use cty::*;
use redbpf_macros::impl_network_buffer_array;

mod error;
mod frame;
mod packet;
mod segment;
mod socket;
mod xdp;
mod tc;
mod socket_filter;

pub struct DataBuf<'a, T> where T: RawBuf {
    /// The underlying memory
    buf: &'a mut T,
    /// Offset from `buf.start()` where the next header/body begins
    nh_offset: usize,
    /// Offset from `buf.start()` where the footer begins
    ftr_offset: usize,
}

impl<'a, T: RawBuf> Packet for DataBuf<'a, T> {
    fn buf<'a, T>(self) -> DataBuf<'a, T> {
        self
    }
}

impl<'a, T: RawBufMut> PacketMut for DataBuf<'a, T> {}

pub trait FromBe {
    fn from_be(&self) -> Self;
}

macro_rules! impl_from_be {
    ($T:ty) => {
        impl FromBe for $T {
            fn from_be(&self) -> $T {
                $T::from_be(*self)
            }
        }
    };
}

impl_from_be!(u8);
impl_from_be!(u16);
impl_from_be!(u32);

pub trait Packet: RawBuf {
    fn buf<'a, T>(self) -> DataBuf<'a, T>;

    /// Interprets the first `size_of::<T>()` bytes in this buffer as some type
    /// `T`, "consuming" `size_of::<T>()` bytes from the buffer.
    fn parse<U>(self) -> Result<U> where U: Packet + FromBytes {
        U::from_bytes(self.buf())
    }
}

pub trait PacketMut: RawBufMut + Packet {
    fn parse_mut<U>(self) -> Result<U> where U: PacketMut + FromBytes {
        U::from_bytes(self.buf())
    }
}

unsafe trait FromBytes {
    fn from_bytes<T>(buf: mut DataBuf<'a, T>) -> Result<Self>;
}
