use anyhow::{anyhow, Result};
use derivative::Derivative;
use strum_macros::EnumIter;
pub const MAGIC_NUMBERS: u16 = u16::from_be_bytes([0x26, 0x2a]);

pub type GdpName = [u8; 32];

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, EnumIter)]
pub enum GdpAction {
    Noop = 0,
    Put = 1,
    Get = 2,
    RibGet = 3,
    RibReply = 4,
    Forward = 5,
    Nack = 6,
    Control = 7,
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
            x if x == GdpAction::Forward as u8 => Ok(GdpAction::Forward),
            x if x == GdpAction::Nack as u8 => Ok(GdpAction::Nack),
            _ => Err(anyhow!("Unknown action byte")),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default)]
pub struct u16be(u16);

impl From<u16> for u16be {
    fn from(item: u16) -> Self {
        u16be(u16::to_be(item))
    }
}

impl From<u16be> for u16 {
    fn from(item: u16be) -> Self {
        u16::from_be(item.0)
    }
}

#[derive(Clone, Copy, Debug, Derivative)]
#[derivative(Default)]
#[repr(C)]
pub struct GdpHeader {
    pub field: u16be, // nonce used to identify GDP packets
    #[derivative(Default(value = "64"))]
    pub ttl: u8, // number of GDP-level hops remaining before packet is dropped
    pub action: u8,   // GDP_ACTION enum
    pub src: GdpName, // 256-bit source
    pub dst: GdpName, // 256-bit destination
    pub last_hop: GdpName, // most recent hop (updated on forwarding)

    // size of data payload (format is header -> data -> certs)
    // this is so we can easily append a cert without an extra copy
    pub data_len: u16be,
}
