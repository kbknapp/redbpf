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
    net::{
        error::Result,
        layer2::L2Proto,
    },
};

/// A pointer to a Network Buffer of raw bytes that came off the wire. `T`
/// determines if the bytes are directly mutable (as in [`XdpContext`]) or not (
/// as in [`SkBuff`]). This struct keeps a cursor into the buffer to keep track
/// of currently parsed headers and the current offset of the next header and/or body.
pub struct NetBuf<'a, T: 'a> {
    /// The raw buffer of underlying memory and how all parsing will take place
    buf: &'a mut T,
    /// Offset from `buf.start()` where the next header/body begins
    nh_offset: usize,
    /// Offset from `buf.start()` where the footer begins
    ftr_offset: usize,
}

impl<'a, T: RawBuf> RawBuf for NetBuf<'a, T> {
    fn start(&self) -> usize {
        self.buf.start()
    }
    fn end(&self) -> usize {
        self.buf.end()
    }
}

impl<'a, T> Packet for NetBuf<'a, T> {
    type Encapsulated = L2Proto<'a, T>;
    fn buf(self) -> NetBuf<'a, T> {
        self
    }

    fn parse_as(self) -> Result<Self::Encapsulated> {
        todo!("impl Packet::parse_from for NetBuf")
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
pub trait Packet : Sized {
    type Encapsulated: Packet + FromBytes;

    fn buf<'a, T>(&self) -> &NetBuf<'a, T>;

    /// Interprets the first `size_of::<U>()` bytes in this buffer as some type
    /// `U`, "consuming" `size_of::<U>()` bytes from the buffer.
    ///
    /// # Safety
    ///
    /// In the default implementation the only checks that are done are to
    /// ensure the buffer contains enough bytes from the start to hold a type of
    /// `U`. However no checks are done to ensure the bytes represent a valid
    /// bit pattern for a type of `U`, nor is any alignment checked.
    unsafe fn parse_as_unchecked<T, U>(self) -> Result<U>
    where
        U: Packet + FromBytes,
        T: RawBuf,
    {
        U::from_bytes::<T>(self.buf())
    }

    /// Parses the next bytes of a [`NetBuf`] as some further encapsulated
    /// packet type.
    ///
    /// Implementors should perform all safety to checks to ensure that the
    /// bytes being parsed represent a valid return type, and check all bounds.
    ///
    /// If multiple inner packet types are possible (such as Ethernet can
    /// encapsulate both TCP or UDP) then `Packet::Encapsulated` should be an
    /// enum which contains variants for all supported encapsulated protocols.
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
    fn parse_as(self) -> Result<Self::Encapsulated>;
}

unsafe trait FromBytes : Sized {
    fn from_bytes<'a, T>(buf: &NetBuf<'a, T>) -> Result<Self>;
}
