/// Represents the Layer 3 information
pub trait Packet: RawBuf {

}

    /// Returns the packet's `IP` header if present.
    #[inline]
    fn ip(&self) -> NetworkResult<*const iphdr> {
        let eth = self.eth()?;
        unsafe {
            if (*eth).h_proto != u16::from_be(ETH_P_IP as u16) {
                return Err(NetworkError::NoIPHeader);
            }

            self.ptr_after(eth)
        }
    }

    /// Returns the packet's transport header if present.
    #[inline]
    fn transport(&self) -> NetworkResult<Transport> {
        unsafe {
            let ip = self.ip()?;
            let addr = ip as usize + ((*ip).ihl() * 4) as usize;
            let transport = match (*ip).protocol as u32 {
                IPPROTO_TCP => (Transport::TCP(self.ptr_at(addr)?)),
                IPPROTO_UDP => (Transport::UDP(self.ptr_at(addr)?)),
                t => return Err(NetworkError::UnsupportedTransport(t)),
            };

            Ok(transport)
        }
    }

    /// Returns the packet's data starting after the transport headers.
    #[inline]
    fn data(&self) -> NetworkResult<Data<Self>> {
        use Transport::*;
        unsafe {
            let base: *const c_void = match self.transport()? {
                TCP(hdr) => {
                    let mut addr = hdr as usize + mem::size_of::<tcphdr>();
                    let data_offset = (*hdr).doff();
                    if data_offset > 5 {
                        addr += ((data_offset - 5) * 4) as usize;
                    }
                    self.ptr_at(addr)
                }
                UDP(hdr) => self.ptr_after(hdr),
            }?;

            let ctx: Self = self.clone();
            Ok(Data {
                ctx,
                base: base as usize,
            })
        }
    }
