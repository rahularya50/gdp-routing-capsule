use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::RwLock;

pub type GdpName = u32;

pub struct SharedCache<K, V>(&'static RwLock<HashMap<K, V>>)
where
    K: 'static,
    V: 'static;

#[derive(Copy, Clone)]
pub struct SyncCache<K, V>
where
    K: 'static,
    V: 'static,
{
    local: &'static RefCell<HashMap<K, V>>,
    global: &'static RwLock<HashMap<K, V>>,
}

impl<K, V> SharedCache<K, V> {
    fn new() -> Self {
        Self(Box::leak(Box::new(RwLock::new(HashMap::new()))))
    }

    fn sync(self: &Self) -> SyncCache<K, V> {
        SyncCache {
            local: Box::leak(Box::new(RefCell::new(HashMap::new()))),
            global: self.0,
        }
    }
}

impl<K, V> SyncCache<K, V>
where
    K: Eq + Hash + Copy,
    V: Clone,
{
    pub fn get(self: &Self, k: &K) -> Option<V> {
        self.local
            .borrow()
            .get(k)
            .cloned()
            .or_else(|| self.global.read().unwrap().get(k).cloned())
    }

    pub fn put(self: &Self, k: K, v: V) {
        if !self.local.borrow().contains_key(&k) {
            self.local.borrow_mut().insert(k, v.clone());
            self.global.write().unwrap().insert(k, v);
        }
    }
}

pub struct SharedStore {
    forwarding_table: SharedCache<GdpName, Ipv4Addr>,
}

impl SharedStore {
    fn new() -> SharedStore {
        SharedStore {
            forwarding_table: SharedCache::new(),
        }
    }
    pub fn sync(self: &Self) -> Store {
        Store {
            forwarding_table: self.forwarding_table.sync(),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Store {
    pub forwarding_table: SyncCache<GdpName, Ipv4Addr>,
}

impl Store {
    pub fn new() -> Self {
        Self::new_shared().sync()
    }

    pub fn new_shared() -> SharedStore {
        SharedStore::new()
    }
}
