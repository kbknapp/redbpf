//! Socket related type and functions

use core::mem::{size_of, MaybeUninit};

use crate::{
    bindings::*,
    helpers::bpf_skb_load_bytes,
    net::FromBe,
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
    #[inline]
    /// Loads data from the socket buffer.
    ///
    /// # Example
    /// ```no_run
    /// use core::mem;
    /// use memoffset::offset_of;
    /// use redbpf_probes::socket_filter::prelude::*;
    ///
    /// #[socket_filter]
    /// fn forward_tcp(skb: SkBuff) -> SkBuffResult {
    ///     let eth_len = mem::size_of::<ethhdr>();
    ///     let eth_proto: u16 = skb.load(offset_of!(ethhdr, h_proto))?;
    ///     let ip_proto: u8 = skb.load(eth_len + offset_of!(iphdr, protocol))?;
    ///
    ///     // only parse TCP
    ///     if !(eth_proto as u32 == ETH_P_IP && ip_proto as u32 == IPPROTO_TCP) {
    ///         return Ok(SkBuffAction::Ignore);
    ///     }
    ///     Ok(SkBuffAction::SendToUserspace)
    /// }
    /// ```
    pub fn load<T: FromBe>(&self, offset: usize) -> Result<T, SocketError> {
        unsafe {
            let mut data = MaybeUninit::<T>::uninit();
            let ret = bpf_skb_load_bytes(
                self.skb as *const _,
                offset as u32,
                &mut data as *mut _ as *mut _,
                size_of::<T>() as u32,
            );
            if ret < 0 {
                return Err(SocketError::LoadFailed);
            }

            Ok(data.assume_init().from_be())
        }
    }
}
