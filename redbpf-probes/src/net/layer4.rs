// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod tcp;

use crate::{
    buf::RawBuf,
    net::{NetBuf, Packet},
};

use self::tcp::Tcp;

use super::FromBytes;

#[non_exhaustive]
pub enum L4Proto<'a, T> {
    Tcp(Tcp<'a, T>),
}

impl<'a, T> L4Proto<'a, T> {
    fn inner_buf(self) -> NetBuf<'a, T> {
        use crate::net::Packet;

        match self {
            L4Proto::Tcp(tcp) => tcp.buf(),
            _ => unimplemented!(),
        }
    }
}

impl<'a, T> Packet for L4Proto<'a, T> {
    type Encapsulated = NetBuf<'a, T>;

    fn buf(self) -> NetBuf<'a, T> {
        self.inner_buf()
    }
}

unsafe impl<'a, T> FromBytes for L4Proto<'a, T> {
    fn from_bytes(buf: NetBuf<'a, T>) -> Self {
        unimplemented!()
    }
}
