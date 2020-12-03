// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Types and traits for working with networking data.

The main trait exported by this module is `NetworkBuffer`. It's implemented
by
[`XdpContext`](https://ingraind.org/api/redbpf_probes/xdp/struct.XdpContext.html)
to provide access to the network data.
 */

mod error;
mod layer2;
mod layer3;
mod layer4;
mod socket;
mod socket_filter;
mod tc;
mod xdp;

use crate::{
    buf::RawBuf,
        net::error::{Result},
};

pub struct DataBuf<'a, T>
where
    T: RawBuf,
{
    /// The underlying memory
    buf: &'a mut T,
    /// Offset from `buf.start()` where the next header/body begins
    nh_offset: usize,
    /// Offset from `buf.start()` where the footer begins
    ftr_offset: usize,
}

impl<'a, T: RawBuf> Packet for DataBuf<'a, T> where T: RawBuf{
    fn buf(self) -> DataBuf<'a, T> {
        self
    }
}

pub trait FromBe {
    fn from_be(&self) -> Self;
}

macro_rules! impl_from_be {
    ($T:ty) => {
        impl FromBe for $T {
            fn from_be(&self) -> $T {
                <$T>::from_be(*self)
            }
        }
    };
}

impl_from_be!(u8);
impl_from_be!(u16);
impl_from_be!(u32);

/// A `Packet` is an abstract idea of bytes coming off the wire making a network
/// message. `Packet`s are recursive (i.e. they encapsulate other `Packet`s).
///
/// An example is an [`Ethernet`] frame which then encapsulates an [`Ipv4`]
/// packet, which further encapsulates a [`Tcp`] a segment, finllay containing
/// some application payload.
///
/// ```no_run
/// +-------------------------------+
/// | Ethernet | IP | TCP | Payload |
/// +-------------------------------+
/// ```
///
/// All implementors of this trait contain an underlying buffer ([`DataBuf`])
/// which represents the actual bytes on the wire. In some BPF contexts the
/// bytes in the buffer are the actual bytes from the network packet and thus
/// directly mutable while in other contexts the bytes only represent the in
/// kernel bytes and must be mutated via BPF helper functions.
///
/// This trait consists of several methods, one to access and pass on the
/// underlying buffer in order to pass it down the stack into the encapsulated
/// packet.
///
/// Another to "parse" the bytes at the current position of the buffer as some
/// further encapsulated packets. For example, if we have an [`Ethernet`] frame,
/// and call [`Packet::parse<Ipv4>`] (requesting an [`Ipv4`] packet), the bytes
/// at the current position of the underlying buffer are interpretted as the
/// requested packet type, and the position in the buffer is advanced to the end
/// of requested packet header.
///
/// ```
/// Currently have an Ethernet frame:
///
/// +-------------------------------+
/// | Ethernet | IP | TCP | Payload |
/// +-------------------------------+
///            ^~~ Current position
///
/// After calling Ethernet::parse<Ipv4>()
///
/// +-------------------------------+
/// | Ethernet | IP | TCP | Payload |
/// +-------------------------------+
///                 ^~~ Current position
///
/// After calling Ipv4::parse<Tcp>()
///
/// +-------------------------------+
/// | Ethernet | IP | TCP | Payload |
/// +-------------------------------+
///                       ^~~ Current position
/// ```
///
/// The `Packet::parse` method is fallible so that if the requested packet type
/// does not match the bytes in the buffer, the caller can be notified. However,
/// not all implementors have good methods to determine if the bytes in the
/// buffer match the requested type (assuming the buffer contains at least
/// enough remaining bytes to satisfy the request). Such an example would be
/// when requesting a [`Ethernet`] frame from a bare [`DataBuf`]. In such
/// circumstances it is up to the caller to ensure the returned structure is a
/// valid instance of the requested type.
///
/// In order to implement [`Packet::parse`] the requested type must meet a few invariants:
///
/// * Must have an alignment of 1 (or use `#[repr(C, packed)]`, which uses an
///   alignment of 1)
/// * Must also implement `Packet`
pub trait Packet: RawBuf + Sized {
    type Encapsulated;
    fn buf<'a, T>(self) -> DataBuf<'a, T> where T: RawBuf;

    /// Interprets the first `size_of::<U>()` bytes in this buffer as some type
    /// `U`, "consuming" `size_of::<U>()` bytes from the buffer.
    fn parse<T, U>(self) -> Result<U>
    where
        U: Packet + FromBytes,
        T: RawBuf,
    {
        U::from_bytes::<T>(self.buf())
    }

    /// Uses some condition to determine the type that the bytes will be parsed
    /// as. `Packet::Encapsulated` should be an enum which contains tuple
    /// variants for all supported encapsulated protocols. Although there is no
    /// way for Rust to enforce this constraint, all inner values of each tuple
    /// variant must implement [`Packet`] and [`FromBytes`].
    ///
    /// For example, if we have a [`Ethernet`] and are unsure whether the next
    /// encapsulated packet is a [`Tcp`] or [`Udp`], but this can be determined
    /// by looking at [`Ethernet::proto`]. This method is implemented on
    /// [`Ethernet`] in such a manner as to look at the `proto` field and return
    /// the correct variant based on the `proto` value.
    ///
    /// **PRO TIP:** If `Packet::Encapsulated` could potentially have additional
    /// protocols or variants added later it should be a [non-exhaustive][0]
    /// enums, or hidden variants (`#[doc(hidden)]`) if required to support a
    /// `rustc` older than 1.40.
    ///
    /// [0]: https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute
    fn parse_from(self) -> Result<Self::Encapsulated>;
}

unsafe trait FromBytes : Sized {
    fn from_bytes<'a, T>(buf: DataBuf<'a, T>) -> Result<Self> where T: RawBuf ;
}
