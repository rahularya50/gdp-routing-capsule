use std::collections::HashMap;
use std::sync::RwLock;

struct StoreContents {
    lookup: HashMap<[u8; 32], [u8; 32]>,
}

#[derive(Copy, Clone)]
pub struct Store(&'static RwLock<StoreContents>);

impl Store {
    pub fn new() -> Self {
        Store(Box::leak(Box::new(RwLock::new(StoreContents {
            lookup: HashMap::new(),
        }))))
    }

    fn with_mut_contents<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut StoreContents) -> T,
    {
        f(&mut self.0.write().unwrap())
    }

    fn with_contents<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&StoreContents) -> T,
    {
        f(&self.0.read().unwrap())
    }

    pub fn put(&self, k: [u8; 32], v: [u8; 32]) {
        self.with_mut_contents(|store| store.lookup.insert(k, v));
    }

    pub fn get(&self, k: &[u8; 32]) -> Option<[u8; 32]> {
        self.with_contents(|store| store.lookup.get(k).cloned())
    }
}
