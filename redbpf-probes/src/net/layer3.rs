// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod ipv4;

pub use ipv4::Ipv4;

use super::{FromBytes, NetBuf, Packet, layer4::L4Proto};

// Because Rust enums have a size of their greatest variant we must ensure that
// all variants have the exact same size, otherewise the verifier may reject
// creation of this enum when smaller variants are used and padding bytes end up
// inserted.
//
// The way we do this is by each variant containing exactly two fields, a
// mutable raw pointer to the header from the kernel bindings, and the NetBuf it
// was created from.
/// An enum with variants for each Layer 3 protocol that can be encapsulted by Layer 2.
#[non_exhaustive]
pub enum L3Proto<'a, T> {
    Ipv4(Ipv4<'a, T>),
}

impl<'a, T> L3Proto<'a, T> {
    fn inner_buf(self) -> NetBuf<'a, T> {
        match self {
            L3Proto::Ipv4(ip) => ip.buf(),
            _ => unimplemented!(),
        }
    }
}

impl<'a, T> Packet for L3Proto<'a, T> {
    type Encapsulated = L4Proto<'a, T>;

    fn buf(self) -> NetBuf<'a, T> {
        self.inner_buf()
    }
}

unsafe impl<'a, T> FromBytes for L3Proto<'a, T> {
    fn from_bytes(buf: NetBuf<'a, T>) -> Self {
        unimplemented!()
    }
}
