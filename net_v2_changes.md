# Renamed

The following were renamed/moved to follow Rust naming conventions and idioms

- `net::NetworkBuffer` -> `crate::buf::RawBuf` (exposed as `crate::RawBuf`)
- `net::NetworkError` -> `net::error::Error` (exposed as `net::Error`)
- `net::NetworkResult` -> `net::error::Result` (exposed as `net::Result`)

# Moved

All code under `redbpf-probes/src/net.rs` has been moved and split accross
`redbpf-probes/src/net/` to allow more separation and future expansion.

# Core Changes

The following core changes were made.

## Moves `redbpf-probes::xpd::MapData` and `redbpf::xdp::MapData` to `bpf-sys::map::MapData`

Instead of manually keeping these types in sync it moves them to a common
dependency.

## Removes `redbpf-probes::net::Data`

It's purpose is essentially served by `redbpf-probes::RawBuf`

## Removes `redbpf-probes::net::NetworkBufferArray` and `redbpf-macros::impl_network_buffer_array`

No longer required

## `crate::RawBuf`/`crate::RawBufMut` (previously `net::NetworkBuffer`)

The motivation behind the change is to allow this buffer to be more abstract for
other uses and not solely coupled with network or XDP uses. Other networking
areas of BPF are not quite as fitting with the old `net::NetworkBuffer` and thus
this changes lowers the buffer in the stack so that it's more general and can be
built on further.

The only functionality this buffer should expose is pointer arithmatic, getting
a raw pointer (mutable or not), offset calculations, and bounds checking.

### List of Changes

In addition the name change, the following changes were made:

- REMOVES: trait bounds `Self: Sized + Clone`
  - It is more idiomatic to require `Sized` or specific bounds on trait methods,
    than the entire trait implementor
- ADDS: trait and method documentation
  - The top level trait, as well as all methods have been documented to include
    `# Safety` sections for `unsafe` methods
- RENAMES: `data_start` -> `start`
  - `net::RawBuf` has no knowledge of packet internals yet, this was moved to
    `??????????`. Thus only start and end address of the entire buffer are known
- RENAMES: `data_end` -> `end`
  - `net::RawBuf` has no knowledge of packet internals yet, this was moved to
    `??????????`. Thus only start and end address of the entire buffer are known
- MODIFIES: `net::RawBuf::check_bounds`
  - Condenses the `if` statement
- ADDS: `ptr_at_mut` and `ptr_after_mut`
  - Returns raw or raw mutable pointers
- ADDS: `as_ptr` and `as_ptr_mut`
  - Returns raw or raw mutable pointers of the entire buffer
- ADDS: `offset` and `offset_mut`
  - Returns raw or raw mutable pointers at offset from `RawBuf::start`
- ADDS: `slice(len)`
  - Returns a slice of bytes from `offset` and `len` bytes
- ADDS: `as_slice`
  - Returns a slice of bytes of the whole buffer
