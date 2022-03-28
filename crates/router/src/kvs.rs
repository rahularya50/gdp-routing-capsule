use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gdp_client::GdpName;
use lru::LruCache;

use crate::certificates::{CertContents, Certificate, GdpMeta, RtCert};
pub trait Expirable {
    fn is_expired(&self) -> bool;
}

#[derive(Copy, Clone, Debug)]
pub struct FwdTableEntry<T> {
    pub val: T,
    pub expiration_time: u64,
}

impl<T> FwdTableEntry<T> {
    pub fn new(val: T, expiration_time: u64) -> Self {
        FwdTableEntry {
            val,
            expiration_time,
        }
    }
}

impl<T> Expirable for FwdTableEntry<T> {
    fn is_expired(&self) -> bool {
        Duration::from_secs(self.expiration_time)
            < SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
    }
}

impl Expirable for Certificate {
    fn is_expired(&self) -> bool {
        match self.contents {
            CertContents::RtCert(RtCert {
                expiration_time, ..
            }) => {
                // RtCerts should last for at least one hour, or we should regenerate them
                // we normally create them to last for four hours
                Duration::from_secs(expiration_time)
                    < SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .add(Duration::from_secs(60 * 60))
            }
        }
    }
}

pub struct SharedCache<K, V>(&'static RwLock<HashMap<K, V>>)
where
    K: 'static,
    V: 'static;

impl<K, V> Copy for SharedCache<K, V> {}
impl<K, V> Clone for SharedCache<K, V> {
    fn clone(&self) -> Self {
        SharedCache(self.0)
    }
}

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

pub struct SyncCache<K, V>
where
    K: 'static,
    V: 'static,
{
    local: &'static RefCell<LruCache<K, V>>,
    global: &'static RwLock<HashMap<K, V>>,
}

impl<K, V> Copy for SyncCache<K, V> {}
impl<K, V> Clone for SyncCache<K, V> {
    fn clone(&self) -> Self {
        SyncCache {
            local: self.local,
            global: self.global,
        }
    }
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
    forwarding_table: SharedCache<GdpName, FwdTableEntry<Ipv4Addr>>,
    next_hops: SharedCache<GdpName, FwdTableEntry<GdpName>>,
    nack_reply_cache: SharedCache<GdpName, FwdTableEntry<Ipv4Addr>>,
    gdp_metadata: SharedCache<GdpName, GdpMeta>,
    route_certs: SharedCache<GdpName, Certificate>,
}

impl SharedStore {
    pub fn new() -> SharedStore {
        SharedStore {
            forwarding_table: SharedCache::new(),
            next_hops: SharedCache::new(),
            nack_reply_cache: SharedCache::new(),
            gdp_metadata: SharedCache::new(),
            route_certs: SharedCache::new(),
        }
    }

    pub fn sync(&self) -> Store {
        Store {
            forwarding_table: self.forwarding_table.sync(),
            next_hops: self.next_hops.sync(),
            nack_reply_cache: self.nack_reply_cache.sync(),
            gdp_metadata: self.gdp_metadata.sync(),
            route_certs: self.route_certs.sync(),
        }
    }

    pub fn run_active_expire(&self) {
        self.forwarding_table.run_active_expire();
        self.nack_reply_cache.run_active_expire();
        self.route_certs.run_active_expire();
    }
}
#[derive(Copy, Clone)]
pub struct Store {
    /// The IP addresses indicating where to forward packets destined for each GdpName
    /// Includes both cached responses from the RIB (pointing to peer switches),
    /// and semi-permanent records from our local domain (pointing to clients or child switches)
    pub forwarding_table: SyncCache<GdpName, FwdTableEntry<Ipv4Addr>>,
    /// The GdpNames of switches delegated to particular target GdpNames outside our local domain
    pub next_hops: SyncCache<GdpName, FwdTableEntry<GdpName>>,
    /// The IP addresses of nodes that previously sent us packets originating from each GdpName
    pub nack_reply_cache: SyncCache<GdpName, FwdTableEntry<Ipv4Addr>>,
    /// The metadata associated with GdpNames
    pub gdp_metadata: SyncCache<GdpName, GdpMeta>,
    /// Route certs we have issued delegating our representation to another GdpName
    pub route_certs: SyncCache<GdpName, Certificate>,
}
