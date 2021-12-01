use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::RwLock;

pub type GdpName = u32;

#[derive(Copy, Clone)]
pub struct SyncCache<K, V>
where
    K: 'static,
    V: 'static,
{
    local: &'static RefCell<HashMap<K, V>>,
    global: &'static RwLock<HashMap<K, V>>,
}

impl<K, V> SyncCache<K, V>
where
    K: Eq + Hash,
{
    fn new() -> Self {
        SyncCache {
            local: Box::leak(Box::new(RefCell::new(HashMap::new()))),
            global: Box::leak(Box::new(RwLock::new(HashMap::new()))),
        }
    }

    fn fork(self: &Self) -> Self {
        SyncCache {
            local: Box::leak(Box::new(RefCell::new(HashMap::new()))),
            global: self.global,
        }
    }

    pub fn get(self: &Self, k: &K) -> Option<&V> {
        self.local
            .borrow()
            .get(k)
            .or_else(|| self.global.read().unwrap().get(k))
    }

    pub fn put(self: &Self, k: K, v: V) {
        if !self.local.borrow().contains_key(&k) {
            self.local.borrow_mut().insert(k, v);
            self.global.write().unwrap().insert(k, v);
        }
    }
}

#[derive(Copy, Clone)]
pub struct Store {
    pub forwarding_table: SyncCache<GdpName, Ipv4Addr>,
}

impl Store {
    pub fn new() -> Self {
        Store {
            forwarding_table: SyncCache::new(),
        }
    }

    pub fn fork(self: &Self) -> Self {
        Store {
            forwarding_table: self.forwarding_table.fork(),
        }
    }
}
