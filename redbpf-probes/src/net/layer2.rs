// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Layer 2 frame handling
mod eth;

pub use eth::Ethernet;

use crate::net::{error::Result, layer3::L3Proto, Packet, NetBuf, FromBytes};

#[non_exhaustive]
pub enum L2Proto<'a, T> {
    Ethernet(Ethernet<'a, T>),
}

impl<'a, T> L2Proto<'a, T> {
    fn inner_buf(self) -> NetBuf<'a, T> {
        match self {
            L2Proto::Ethernet(eth) => eth.buf(),
            _ => unimplemented!(),
        }
    }
}

impl<'a, T> Packet for L2Proto<'a, T> {
    type Encapsulated = L3Proto<'a, T>;

    fn buf(self) -> NetBuf<'a, T> {
        self.inner_buf()
    }
}

unsafe impl<'a, T> FromBytes for L2Proto<'a, T> {
    fn from_bytes(buf: NetBuf<'a, T>) -> Self {
        unimplemented!()
    }
}
