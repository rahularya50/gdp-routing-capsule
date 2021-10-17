use capsule::packets::ip::{IpPacket};
use capsule::packets::types::u16be;
use capsule::packets::{Internal, Packet};
use capsule::{ensure, SizeOf};
use anyhow::{anyhow, Result};
use std::fmt;
use std::ptr::NonNull;
use capsule::packets::Udp;

const MAGIC_NUMBERS: [u8; 2] = [0x26, 0x2a];

pub struct Gdp<T: IpPacket> {
    envelope: Udp<T>,
    header: NonNull<GdpHeader>,
    offset: usize,
}

impl<T: IpPacket> Gdp<T> {
    #[inline]
    fn header(&self) -> &GdpHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut GdpHeader {
        unsafe { self.header.as_mut() }
    }

    #[inline]
    pub fn field(&self) -> u16 {
        self.header().field.into()
    }

    #[inline]
    pub fn set_field(&mut self, src_port: u16) {
        self.header_mut().field = src_port.into();
    }
}

impl<T: IpPacket> fmt::Debug for Gdp<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("gdp")
            .field("$field", &self.field())
            .finish()
    }
}

impl<T: IpPacket> Packet for Gdp<T> {
    type Envelope = Udp<T>;

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        &self.envelope
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        &mut self.envelope
    }

    #[inline]
    fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn header_len(&self) -> usize {
        GdpHeader::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Gdp {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        let out = Gdp {
            envelope,
            header,
            offset,
        };

        ensure!(
            out.header().field == u16be::from(u16::from_be_bytes(MAGIC_NUMBERS)),
            anyhow!("not a GDP packet.")
        );

        Ok(out)
    }

    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, GdpHeader::size_of())?;
        let header = mbuf.write_data(offset, &GdpHeader::default())?;

        Ok(Gdp {
            envelope,
            header,
            offset,
        })
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }

    #[inline]
    fn reconcile(&mut self) {
        // todo
    }
}

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C)]
struct GdpHeader {
    field: u16be,
}

