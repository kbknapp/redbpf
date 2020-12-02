// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[repr(u16)]
pub enum EthProto {
    Ipv4 = ETH_P_IP as u16,
}

pub struct Ethernet {
    hdr: *mut ethhdr,
}

impl Ethernet {
    pub fn source(&self) -> &[u8; 6] {
        &self.inner.h_source
    }
    pub fn dest(&self) -> RawMac {
        &self.inner.h_dest
    }
    pub fn proto(&self) -> EthProto {
        u16::from_be(self.inner.h_proto) as EthProto
    }
}

impl TryFrom<T> for Ethernet where T: crate::net::Buf {
    fn try_from(b: T) -> Option<Self> {
        Ethernet {
            hdr: b.ptr_at(b.as_ptr() as usize)?
        }
    }

}
