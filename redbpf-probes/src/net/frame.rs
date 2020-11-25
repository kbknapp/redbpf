// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// Represents the Layer two header + payload of a raw network buffer.
pub trait Frame: RawBuf {
    /// Returns the packet's Ethernet header if present.
    #[inline]
    fn eth(&self) -> Result<RawEthHeader> {
        Ok(RawEthHeader {
            inner: unsafe { self.ptr_at(self.start() as usize)? }
        })
    }

}
