// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Layer 2 frame handling
mod eth;

pub use eth::Ethernet;

use crate::net::{
    buf::{NetBuf, RawBuf},
    error::Result,
    layer3::{Ipv4, L3Proto},
    FromBytes, Packet,
};

#[non_exhaustive]
pub enum L2Proto<'a, T: RawBuf> {
    Ethernet(Ethernet<'a, T>),
}

impl<'a, T: RawBuf> L2Proto<'a, T> {
    fn inner_buf(self) -> NetBuf<'a, T> {
        match self {
            L2Proto::Ethernet(eth) => eth.data(),
            _ => unimplemented!(),
        }
    }
}

impl<'a, T: RawBuf> Packet<'a, T> for L2Proto<'a, T> {
    type Encapsulated = L3Proto<'a, T>;

    fn data(self) -> NetBuf<'a, T> {
        self.inner_buf()
    }

    fn parse(self) -> Result<Self::Encapsulated> {
        match self {
            L2Proto::Ethernet(ref eth) => match eth.proto() {
                ETH_P_IP => {
                    return Ok(L3Proto::Ipv4(Ipv4::from_bytes(self.data())?));
                }
                _ => unimplemented!(),
            },
            _ => unimplemented!(),
        }
    }
}
