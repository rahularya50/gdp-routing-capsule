use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::prelude::SliceRandom;

pub type GdpName = u32;

#[derive(Copy, Clone)]
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
        let mut m = self.local.borrow_mut();
        if m.contains_key(k) {
            return m.get(k).cloned();
        }

        // Otherwise must hit global cache and update local
        let g_opt = self.global.read().unwrap().get(k).cloned();
        if g_opt.is_some() {
            m.insert(*k, g_opt.as_ref().unwrap().clone());
        }
        g_opt
    }

    pub fn put(self: &Self, k: K, v: V) {
        if !self.local.borrow().contains_key(&k) {
            self.local.borrow_mut().insert(k, v.clone());
            self.global.write().unwrap().insert(k, v);
        }
    }

    pub fn remove(self: &Self, &k: &K) {
        self.local.borrow_mut().remove_entry(&k);
        self.global.write().unwrap().remove_entry(&k);
    }
}

#[derive(Copy, Clone)]
pub struct SharedStore {
    forwarding_table: SharedCache<GdpName, FwdTableEntry>,
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
#[derive(Copy, Clone, Debug)]
pub struct FwdTableEntry {
    pub ip: Ipv4Addr,
    pub expiration_time: u64,
}

impl FwdTableEntry {
    pub fn new(ip: Ipv4Addr, expiration_time: u64) -> Self {
        FwdTableEntry {
            ip,
            expiration_time,
        }
    }

    pub fn is_expired(&self) -> bool {
        Duration::from_secs(self.expiration_time)
            < SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
    }
}

pub struct StoreContents {
    // Mapping from GDPName to target IP and expiration time in Unix epoch
    pub forwarding_table: HashMap<GdpName, FwdTableEntry>,
}

#[derive(Copy, Clone)]
pub struct Store {
    pub forwarding_table: SyncCache<GdpName, FwdTableEntry>,
}

impl Store {
    pub fn new() -> Self {
        Self::new_shared().sync()
    }

    pub fn new_shared() -> SharedStore {
        SharedStore::new()
    }

    pub fn run_active_expire(&mut self) {
        /* This actively expires keys using a probabilistic algorithm used by Redis.
           "Specifically this is what Redis does 10 times per second:
            - Test 20 random keys from the set of keys with an associated expire.
            - Delete all the keys found expired.
            - If more than 25% of keys were expired, start again from step 1."
           https://redis.io/commands/expire

           Specifically for edge case of <= 20 keys we just don't active expire
        */
        let ACTIVE_EXPIRE_CUTOFF = 20;
        let mut expired_proportion = 1.0;

        let mut global_table = self.forwarding_table.global.write().unwrap();
        while expired_proportion > 0.25 {
            let initial_len = global_table.len();
            if initial_len <= ACTIVE_EXPIRE_CUTOFF {
                return;
            }

            // writing fast code is my passion~
            let mut keys: Vec<GdpName> = global_table.keys().cloned().collect();
            let mut rng = rand::thread_rng();
            keys.shuffle(&mut rng);
            let mut removed_count = 0;
            keys.iter().take(ACTIVE_EXPIRE_CUTOFF).for_each(|k| {
                if global_table.get(k).unwrap().is_expired() {
                    global_table.remove_entry(k);
                    removed_count += 1;
                }
            });
            expired_proportion = removed_count as f64 / initial_len as f64;
        }
    }
}
