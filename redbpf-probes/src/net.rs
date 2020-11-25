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

/// The packet transport header.
///
/// Currently only `TCP` and `UDP` transports are supported.
pub enum Transport {
    TCP(*const tcphdr),
    UDP(*const udphdr),
}

impl Transport {
    /// Returns the source port.
    #[inline]
    pub fn source(&self) -> u16 {
        let source = match *self {
            Transport::TCP(hdr) => unsafe { (*hdr).source },
            Transport::UDP(hdr) => unsafe { (*hdr).source },
        };
        u16::from_be(source)
    }

    /// Returns the destination port.
    #[inline]
    pub fn dest(&self) -> u16 {
        let dest = match *self {
            Transport::TCP(hdr) => unsafe { (*hdr).dest },
            Transport::UDP(hdr) => unsafe { (*hdr).dest },
        };
        u16::from_be(dest)
    }
}

/// Data type returned by calling `NetworkBuffer::data()`
pub struct Data<T: NetworkBuffer> {
    ctx: T,
    base: usize,
}

impl<T: NetworkBuffer> Data<T> {
    /// Returns the offset from the first byte of the packet.
    #[inline]
    pub fn offset(&self) -> usize {
        self.base - self.ctx.data_start()
    }

    /// Returns the length of the data.
    ///
    /// This is equivalent to the length of the packet minus the length of the headers.
    #[inline]
    pub fn len(&self) -> usize {
        self.ctx.data_end() - self.base
    }

    /// Returns a `slice` of `len` bytes from the data.
    #[inline]
    pub fn slice(&self, len: usize) -> NetworkResult<&[u8]> {
        unsafe {
            self.ctx.check_bounds(self.base, self.base + len)?;
            let s = slice::from_raw_parts(self.base as *const u8, len);
            Ok(s)
        }
    }

    #[inline]
    pub fn read<U: NetworkBufferArray>(&self) -> NetworkResult<U> {
        unsafe {
            let len = mem::size_of::<U>();
            self.ctx.check_bounds(self.base, self.base + len)?;
            Ok((self.base as *const U).read_unaligned())
        }
    }
}

pub trait NetworkBufferArray {}
impl_network_buffer_array!();
