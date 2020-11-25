// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[repr(u32)]
pub enum EtherProto {
    Ipv4 = ETH_P_IP,
}
pub struct RawMac {
    inner: *mut [u8; 6]
}

pub struct RawEthHeader {
    inner: *mut ethhdr
}

impl RawEthHeader {
    pub fn source(&mut self) -> RawMac {
        RawMac { inner: self.inner.h_source }
    }
    pub fn dest(&mut self) -> RawMac {
        RawMac { inner: self.inner.h_dest }
    }
    pub fn proto(&mut self) -> EtherProto {
        self.inner.h_proto as EtherProto
    }
}
