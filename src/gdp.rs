use crate::kvs::GdpName;

use anyhow::{anyhow, Result};
use capsule::packets::ip::IpPacket;
use capsule::packets::types::u16be;
use capsule::packets::Udp;
use capsule::packets::{Internal, Packet};
use capsule::{ensure, SizeOf};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ptr::NonNull;
use strum_macros::EnumIter;

const MAGIC_NUMBERS: u16 = u16::from_be_bytes([0x26, 0x2a]);

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, EnumIter)]
pub enum GdpAction {
    Noop = 0,
    Put = 1,
    Get = 2,
    RibGet = 3,
    RibReply = 4,
    Forward = 5,
    Nack = 6,
}

impl Default for GdpAction {
    fn default() -> Self {
        GdpAction::Noop
    }
}

impl TryFrom<u8> for GdpAction {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            x if x == GdpAction::Noop as u8 => Ok(GdpAction::Noop),
            x if x == GdpAction::Get as u8 => Ok(GdpAction::Get),
            x if x == GdpAction::Put as u8 => Ok(GdpAction::Put),
            x if x == GdpAction::RibGet as u8 => Ok(GdpAction::RibGet),
            x if x == GdpAction::RibReply as u8 => Ok(GdpAction::RibReply),
            _ => Err(anyhow::Error::msg("Unknown action byte")),
        }
    }
}

#[derive(Debug)]
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
    pub fn action(&self) -> Result<GdpAction> {
        self.header().action.try_into()
    }

    #[inline]
    pub fn set_action(&mut self, action: GdpAction) {
        self.header_mut().action = action as u8;
    }

    #[inline]
    pub fn key(&self) -> u32 {
        self.header().key
    }

    #[inline]
    pub fn set_key(&mut self, key: u32) {
        self.header_mut().key = key;
    }

    #[inline]
    pub fn value(&self) -> u32 {
        self.header().value
    }

    #[inline]
    pub fn set_value(&mut self, value: u32) {
        self.header_mut().value = value;
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
            out.header().field == MAGIC_NUMBERS.into(),
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
        self.header_mut().field = MAGIC_NUMBERS.into();
    }
}

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C)]
struct GdpHeader {
    field: u16be, // nonce used to identify GDP packets
    ttl: u8,      // number of GDP-level hops remaining before packet is dropped
    action: u8,   // GDP_ACTION enum
    src: GdpName, // 256-bit source
    dst: GdpName, // 256-bit destination
    key: u32,     // query key, used in meta-packets
    value: u32,   // query value, used in meta-packets
}
