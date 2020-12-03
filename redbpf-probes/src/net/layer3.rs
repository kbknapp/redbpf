// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod ipv4;

pub use ipv4::Ipv4;

#[non_exhaustive]
pub enum L3Proto {
    Ipv4(Ipv4),
}
