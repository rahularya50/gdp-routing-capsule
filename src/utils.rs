use capsule::net::MacAddr;

pub trait BroadcastMacAddr {
    fn broadcast() -> MacAddr {
        MacAddr::new(u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX)
    }
}

impl BroadcastMacAddr for MacAddr {}
