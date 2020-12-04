// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Layer 2 frame handling
mod eth;

pub use eth::Ethernet;

use crate::buf::RawBuf;

#[non_exhaustive]
pub enum L2Proto<'a, T: RawBuf> {
    Ethernet(Ethernet<'a, T>),
}
