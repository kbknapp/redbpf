// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
XDP (eXpress Data Path).

XDP provides high performance network processing capabilities in the kernel.
For an overview of XDP and how it works, see
<https://www.iovisor.org/technology/xdp>.

# Example

Block all traffic directed to port 80:

```no_run
#![no_std]
#![no_main]
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[xdp]
fn block_port_80(ctx: XdpContext) -> Result<XdpAction> {
    let transport = ctx.transport()?;
    if transport.dest() == 80 {
        return Ok(XdpAction::Drop);
    }

    Ok(XdpAction::Pass)
}
```
 */

pub mod prelude {
    //! The XDP Prelude
    //!
    //! The purpose of this module is to alleviate imports of the common XDP types
    //! by adding a glob import to the top of XDP programs:
    //!
    //! ```
    //! use redbpf_probes::net::xdp::prelude::*;
    //! ```
    pub use crate::bindings::*;
    pub use crate::helpers::*;
    pub use crate::maps::{HashMap, PerfMapFlags};
    pub use crate::net::xdp::*;
    pub use crate::net::*;
    pub use cty::*;
    pub use redbpf_macros::{map, program, xdp};
}

use crate::{
    bindings::*,
    buf::{RawBuf, RawBufMut},
    maps::{PerfMap as PerfMapBase, PerfMapFlags},
    net::DataBuf,
};

/// The return type for successful XDP probes.
#[repr(u32)]
pub enum XdpAction {
    /// Signals that the program had an unexpected anomaly. Should only be used
    /// for debugging purposes.
    ///
    /// Results in the packet being dropped.
    Aborted = xdp_action_XDP_ABORTED,
    /// The simplest and fastest action. It simply instructs the driver to drop
    /// the packet.
    Drop = xdp_action_XDP_DROP,
    /// Pass the packet to the normal network stack for processing. Note that the
    /// XDP program is allowed to have modified the packet-data.
    Pass = xdp_action_XDP_PASS,
    /// Results in TX bouncing the received packet back to the same NIC it
    /// arrived on. This is usually combined with modifying the packet contents
    /// before returning.
    Tx = xdp_action_XDP_TX,
    /// Similar to `Tx`, but through another NIC.
    Redirect = xdp_action_XDP_REDIRECT,
}

/// Context object provided to XDP programs.
///
/// XDP programs are passed a `XdpContext` instance as their argument. Through
/// the context, programs can inspect, modify and redirect the underlying
/// networking data.
pub struct XdpContext<'a> {
    pub ctx: &'a mut xdp_md,
}

impl<'a> XdpContext<'a> {
    /// Returns the `xdp_md` context passed by the kernel.
    #[inline]
    pub fn inner(&self) -> &mut xdp_md {
        self.ctx
    }

    /// Returns a [`DataBuf`][0] with the header offset set to `0`, and footer offset
    /// set to the end of the data buffer (i.e. no footer) since this is a clean
    /// slate data buffer with no knowledge of what type of data lives inside.
    ///
    /// [0]: crate::net::DataBuf
    pub fn data(&mut self) -> DataBuf<'a, Self> {
        DataBuf {
            buf: self,
            nh_offset: 0,
            ftr_offset: self.ctx.data_end as usize,
        }
    }
}

impl<'a> RawBuf for XdpContext<'a> {
    fn start(&self) -> usize {
        self.ctx.data as usize
    }

    fn end(&self) -> usize {
        self.ctx.data_end as usize
    }
}

impl<'a> RawBufMut for XdpContext<'a> {}

/* NB: this needs to be kept in sync with redbpf::xdp::MapData */
/// Convenience data type to exchange payload data.
#[repr(C)]
pub struct MapData<T> {
    data: T,
    offset: u32,
    size: u32,
    payload: [u8; 0],
}

impl<T> MapData<T> {
    /// Create a new `MapData` value that includes only `data` and no packet
    /// payload.
    pub fn new(data: T) -> Self {
        MapData::<T>::with_payload(data, 0, 0)
    }

    /// Create a new `MapData` value that includes `data` and `size` payload
    /// bytes, where the interesting part of the payload starts at `offset`.
    ///
    /// The payload can then be retrieved calling `MapData::payload()`.
    pub fn with_payload(data: T, offset: u32, size: u32) -> Self {
        Self {
            data,
            payload: [],
            offset,
            size,
        }
    }
}

/// Perf events map.
///
/// Similar to `PerfMap`, with additional XDP-only API.
#[repr(transparent)]
pub struct PerfMap<T>(PerfMapBase<MapData<T>>);

impl<T> PerfMap<T> {
    /// Creates a perf map with the specified maximum number of elements.
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self(PerfMapBase::with_max_entries(max_entries))
    }

    /// Insert a new event in the perf events array keyed by the current CPU number.
    ///
    /// Each array can hold up to `max_entries` events, see `with_max_entries`.
    /// If you want to use a key other than the current CPU, see
    /// `insert_with_flags`.
    ///
    /// `packet_size` specifies the number of bytes from the current packet that
    /// the kernel should append to the event data.
    #[inline]
    pub fn insert(&mut self, ctx: &XdpContext, data: &MapData<T>) {
        let size = data.size;
        self.0
            .insert_with_flags(ctx.inner(), data, PerfMapFlags::with_xdp_size(size))
    }

    /// Insert a new event in the perf events array keyed by the index and with
    /// the additional xdp payload data specified in the given `PerfMapFlags`.
    #[inline]
    pub fn insert_with_flags(
        &mut self,
        ctx: &XdpContext,
        data: &MapData<T>,
        mut flags: PerfMapFlags,
    ) {
        flags.xdp_size = data.size;
        self.0.insert_with_flags(ctx.inner(), data, flags)
    }
}
