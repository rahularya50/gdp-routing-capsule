use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lru::LruCache;

use crate::certificates::GdpMeta;

pub type GdpName = [u8; 32];

pub trait Expirable {
    fn is_expired(&self) -> bool;
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
}

impl Expirable for FwdTableEntry {
    fn is_expired(&self) -> bool {
        Duration::from_secs(self.expiration_time)
            < SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
    }
}

#[derive(Copy, Clone)]
pub struct SharedCache<K, V>(&'static RwLock<HashMap<K, V>>)
where
    K: 'static,
    V: 'static;

impl<K, V> SharedCache<K, V>
where
    K: Eq + Hash + Copy,
    V: Expirable,
{
    fn run_active_expire(&self) {
        /* This actively expires keys using a probabilistic algorithm used by Redis.
           "Specifically this is what Redis does 10 times per second:
            - Test 20 random keys from the set of keys with an associated expire.
            - Delete all the keys found expired.
            - If more than 25% of keys were expired, start again from step 1."
           https://redis.io/commands/expire

           Specifically for edge case of <= 20 keys we just don't active expire
        */
        const ACTIVE_EXPIRE_CUTOFF: usize = 20;
        let mut expired_proportion = 1.0;

        let mut global_table = self.0.write().unwrap();
        while expired_proportion > 0.25 {
            // println!(
            //     "{:?} running active expire on table {:?}",
            //     SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
            //     global_table
            // );
            let initial_len = global_table.len();
            if initial_len <= ACTIVE_EXPIRE_CUTOFF {
                return;
            }

            let sampled_expired_keys = global_table
                .iter()
                .take(ACTIVE_EXPIRE_CUTOFF)
                .filter(|(_, v)| v.is_expired())
                .map(|(k, _)| *k)
                .collect::<Vec<_>>();

            let removed_count = sampled_expired_keys.len();

            for key in sampled_expired_keys {
                global_table.remove_entry(&key);
            }

            expired_proportion = removed_count as f64 / initial_len as f64;
        }
    }
}

#[derive(Copy, Clone)]
pub struct SyncCache<K, V>
where
    K: 'static,
    V: 'static,
{
    local: &'static RefCell<LruCache<K, V>>,
    global: &'static RwLock<HashMap<K, V>>,
}

impl<K: Eq + Hash, V> SharedCache<K, V> {
    fn new() -> Self {
        Self(Box::leak(Box::new(RwLock::new(HashMap::new()))))
    }

    fn sync(&self) -> SyncCache<K, V> {
        SyncCache {
            local: Box::leak(Box::new(RefCell::new(LruCache::new(500)))),
            global: self.0,
        }
    }
}

impl<K, V> SyncCache<K, V>
where
    K: Eq + Hash + Copy + Debug,
    V: Clone + Debug,
{
    pub fn get_unchecked(&self, k: &K) -> Option<V> {
        let mut m = self.local.borrow_mut();
        if m.contains(k) {
            return m.get(k).cloned();
        }

        // Otherwise must hit global cache and update local
        let g_opt = self.global.read().unwrap().get(k).cloned();
        if let Some(ref o) = g_opt {
            m.put(*k, o.clone());
        }
        g_opt
    }

    pub fn put(&self, k: K, v: V) {
        if !self.local.borrow().contains(&k) {
            self.local.borrow_mut().put(k, v.clone());
            self.global.write().unwrap().insert(k, v);
        }
    }

    fn remove(&self, &k: &K) {
        self.local.borrow_mut().pop(&k);
        self.global.write().unwrap().remove_entry(&k);
    }
}

impl<K, V> SyncCache<K, V>
where
    K: Eq + Hash + Copy + Debug,
    V: Clone + Debug + Expirable,
{
    pub fn get(&self, k: &K) -> Option<V> {
        let val = self.get_unchecked(k)?;
        if val.is_expired() {
            self.remove(k);
            None
        } else {
            Some(val)
        }
    }
}
#[derive(Copy, Clone)]
pub struct SharedStore {
    forwarding_table: SharedCache<GdpName, FwdTableEntry>,
    nack_reply_cache: SharedCache<GdpName, FwdTableEntry>,
    gdp_metadata: SharedCache<GdpName, GdpMeta>,
}

impl SharedStore {
    fn new() -> SharedStore {
        SharedStore {
            forwarding_table: SharedCache::new(),
            nack_reply_cache: SharedCache::new(),
            gdp_metadata: SharedCache::new(),
        }
    }

    pub fn sync(&self) -> Store {
        Store {
            forwarding_table: self.forwarding_table.sync(),
            nack_reply_cache: self.nack_reply_cache.sync(),
            gdp_metadata: self.gdp_metadata.sync(),
        }
    }

    pub fn run_active_expire(&self) {
        self.forwarding_table.run_active_expire();
        self.nack_reply_cache.run_active_expire();
    }
}
#[derive(Copy, Clone)]
pub struct Store {
    pub forwarding_table: SyncCache<GdpName, FwdTableEntry>,
    pub nack_reply_cache: SyncCache<GdpName, FwdTableEntry>,
    pub gdp_metadata: SyncCache<GdpName, GdpMeta>,
}

impl Store {
    pub fn new() -> Self {
        Self::new_shared().sync()
    }

    pub fn new_shared() -> SharedStore {
        SharedStore::new()
    }
}
