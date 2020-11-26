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

pub trait MacHeader: RawBuf {
    fn eth(&self) -> Option<RawEthHeader> {
        RawEthHeader {
            inner: self.as_ptr_mut()
        }
    }
}

pub trait NetworkHeader: RawBuf {
    fn ip(&self) -> Option<RawIpHeader> {
        RawEthHeader {
            inner: self.as_ptr_mut()
        }
    }
    fn ipv6(&self) -> Option<RawIpv6Header> {
        RawEthHeader {
            inner: self.as_ptr_mut()
        }
    }
}

pub trait TransportHeader: RawBuf {
    fn tcp(&self) -> Option<RawTcpHeader> {
        RawEthHeader {
            inner: self.as_ptr_mut()
        }
    }
    fn udp(&self) -> Option<RawUdpHeader> {
        RawEthHeader {
            inner: self.as_ptr_mut()
        }
    }
}
