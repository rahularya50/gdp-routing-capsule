use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

use anyhow::{anyhow, Result};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Internal, Packet};
use capsule::{ensure, SizeOf};
use client::{GdpAction, GdpHeader, GdpName, MAGIC_NUMBERS};
use serde::{Deserialize, Serialize};

use crate::certificates::Certificate;
use crate::DTls;

pub struct Gdp<T: Packet> {
    envelope: T,
    header: NonNull<SizedGdpHeader>,
    offset: usize,
}

impl<T: Packet> Gdp<T> {
    #[inline]
    fn header(&self) -> &GdpHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut GdpHeader {
        unsafe { self.header.as_mut() }
    }

    #[inline]
    pub fn action(&self) -> Result<GdpAction> {
        self.header().action.try_into()
    }

    #[inline]
    pub fn set_action(&mut self, action: GdpAction) {
        self.header_mut().action = action as u8;
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.header().ttl
    }

    #[inline]
    pub fn set_ttl(&mut self, ttl: u8) {
        self.header_mut().ttl = ttl;
    }

    #[inline]
    pub fn src(&self) -> GdpName {
        self.header().src
    }

    #[inline]
    pub fn set_src(&mut self, src: GdpName) {
        self.header_mut().src = src;
    }

    #[inline]
    pub fn dst(&self) -> GdpName {
        self.header().dst
    }

    #[inline]
    pub fn set_dst(&mut self, dst: GdpName) {
        self.header_mut().dst = dst;
    }

    #[inline]
    pub fn data_len(&self) -> usize {
        u16::from(self.header().data_len) as usize
    }

    #[inline]
    pub fn set_data_len(&mut self, data_len: usize) {
        self.header_mut().data_len = (data_len as u16).into();
    }

    #[inline]
    pub fn get_certs(&self) -> Result<CertificateBlock> {
        if self.payload_len() - self.data_len() == 0 {
            Ok(CertificateBlock {
                certificates: vec![],
            })
        } else {
            Ok(bincode::deserialize(unsafe {
                self.mbuf()
                    .read_data_slice(
                        self.payload_offset() + self.data_len(),
                        self.payload_len() - self.data_len(),
                    )?
                    .as_ref()
            })?)
        }
    }

    #[inline]
    pub fn set_certs(&mut self, certificates: &CertificateBlock) -> Result<()> {
        let serialized = bincode::serialize(certificates)?; // todo: avoid allocation, write straight into mbuf!
        let cert_offset = self.payload_offset() + self.data_len();
        if self.mbuf().data_len() != cert_offset {
            self.mbuf_mut().truncate(cert_offset)?;
        }
        if !serialized.is_empty() {
            self.mbuf_mut().extend(cert_offset, serialized.len())?;
        }
        self.mbuf_mut().write_data_slice(cert_offset, &serialized)?;
        Ok(())
    }
}

impl fmt::Debug for Gdp<DTls<Ipv4>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ipv4 = self.envelope().envelope().envelope();
        let ethernet = ipv4.envelope();
        f.debug_struct("gdp")
            .field("ttl", &self.ttl())
            .field("action", &self.action())
            .field("src", &self.src())
            .field("dst", &self.dst())
            .field("data_len", &self.data_len())
            .field("ipv4_frame", ipv4)
            .field("eth_frame", ethernet)
            .finish()
    }
}

impl<T: Packet> Packet for Gdp<T> {
    type Envelope = T;

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
        SizedGdpHeader::size_of()
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
            u16::from(out.header().field) == MAGIC_NUMBERS,
            anyhow!("not a GDP packet.")
        );

        Ok(out)
    }

    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, SizedGdpHeader::size_of())?;
        let header = mbuf.write_data(offset, &SizedGdpHeader::default())?;

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
        self.header_mut().field = MAGIC_NUMBERS.into();
    }
}

#[derive(SizeOf, Default)]
struct SizedGdpHeader(GdpHeader);

impl Deref for SizedGdpHeader {
    type Target = GdpHeader;
    fn deref(&self) -> &<Self as Deref>::Target {
        &self.0
    }
}

impl DerefMut for SizedGdpHeader {
    fn deref_mut(&mut self) -> &mut <Self as Deref>::Target {
        &mut self.0
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CertificateBlock {
    pub certificates: Vec<Certificate>,
}
