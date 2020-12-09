//! Socket related type and functions

use core::{
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
};

use crate::{
    bindings::*,
    helpers::bpf_skb_load_bytes,
    net::{
        buf::{NetBuf, RawBuf},
        error::{Error, Result},
        FromBe,
    },
};

// Errors in socket-related programs
pub enum SocketError {
    /// Loading data from the socket buffer failed.
    LoadFailed,
}

/// Context object provided to Socket-related programs.
pub struct SkBuff {
    /// The low level skb instance.
    pub skb: *const __sk_buff,
}

impl SkBuff {
    /// Returns the `__sk_buff` context passed by the kernel.
    #[inline]
    pub fn inner(&mut self) -> &__sk_buff {
        if let Some(ctx) = unsafe { self.skb.as_ref() } {
            return ctx;
        }
        panic!("*__sk_buff is null")
    }

    /// Returns a [`NetBuf`][0] with the header offset set to `0` since this is
    /// a clean slate data buffer with no knowledge of what type of data lives
    /// inside.
    pub fn data<'a>(&'a self) -> NetBuf<'a, Self> {
        NetBuf {
            buf: self as *const _ as *mut _,
            nh_offset: 0,
            _marker: PhantomData,
        }
    }
}

impl RawBuf for SkBuff {
    fn start(&self) -> usize {
        if let Some(ctx) = unsafe { self.skb.as_ref() } {
            return ctx.data as usize;
        }
        panic!("*__sk_buff is null")
    }

    fn end(&self) -> usize {
        if let Some(ctx) = unsafe { self.skb.as_ref() } {
            return ctx.data_end as usize;
        }
        panic!("*__sk_buff is null")
    }

    #[inline]
    fn load_be<T: FromBe>(&self, offset: usize) -> Result<T> {
        self.load(offset).map(|val: T| val.from_be())
    }

    #[inline]
    fn load<T>(&self, offset: usize) -> Result<T> {
        unsafe {
            let mut data = MaybeUninit::<T>::uninit();
            let ret = bpf_skb_load_bytes(
                self.skb as *const _,
                offset as u32,
                &mut data as *mut _ as *mut _,
                size_of::<T>() as u32,
            );
            if ret < 0 {
                return Err(Error::LoadFailed);
            }

            Ok(data.assume_init())
        }
    }
}
