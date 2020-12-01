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

/// A raw network buffer, meaning a pointer to raw bytes representing a packet
pub trait RawBuf: crate::RawBuf {
    /// Returns the layer 2 header from the buffer
    fn mac_header(&self) -> Option<MacHeader>
    /// Returns the layer 3 header from the buffer
    fn network_header(&self) -> Option<NetworkHeader>
    /// Returns the layer 4 header from the buffer
    fn transport_header(&self) -> Option<TransportHeader>
}
