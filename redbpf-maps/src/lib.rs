// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::slice;

#[repr(C)]
pub struct MapData<T> {
    /// The custom data type to be exchanged with user space.
    data: T,
    offset: u32,
    size: u32,
    payload: [u8; 0],
}

impl<T> MapData<T> {
    // /// # Safety
    // ///
    // /// Casts a pointer of `Sample.data` to `*const MapData<U>`
    // pub unsafe fn from_sample<U>(sample: &Sample) -> &MapData<U> {
    //     &*(sample.data.as_ptr() as *const MapData<U>)
    // }

    /// Return the data shared by the kernel space program.
    pub fn data(&self) -> &T {
        &self.data
    }

    // /// Return the XDP payload shared by the kernel space program.
    // ///
    // /// Returns an empty slice if the kernel space program didn't share any XDP payload.
    // pub fn payload(&self) -> &[u8] {
    //     unsafe {
    //         let base = self.payload.as_ptr().add(self.offset as usize);
    //         slice::from_raw_parts(base, (self.size - self.offset) as usize)
    //     }
    // }
}
