use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

pub type GdpName = u32;

pub struct StoreContents {
    pub forwarding_table: HashMap<GdpName, Ipv4Addr>, // for this switch, this tells us the IP address of the next hop for a given target
}

#[derive(Copy, Clone)]
pub struct Store(&'static RwLock<StoreContents>);

impl Store {
    pub fn new() -> Self {
        Store(Box::leak(Box::new(RwLock::new(StoreContents {
            forwarding_table: HashMap::new(),
        }))))
    }

    pub fn with_mut_contents<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut StoreContents) -> T,
    {
        f(&mut self.0.write().unwrap())
    }

    pub fn with_contents<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&StoreContents) -> T,
    {
        f(&self.0.read().unwrap())
    }
}
