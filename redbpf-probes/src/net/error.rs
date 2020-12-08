// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::result::Result as StdResult;

pub enum Error {
    Other,
    OutOfBounds,
    NoIPHeader,
    UnsupportedTransport(u32),
    TypeFromBytes,
    UnknownProtocol,
    WrongProtocol
    //    NoneValueReturned
}

pub type Result<T> = StdResult<T, Error>;

// impl From<NoneError> for Error {
//     fn from(n: NoneError) -> Self {
//         Err(Error::NoneValueReturned)
//     }
// }
