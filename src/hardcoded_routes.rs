use std::fs;
use std::sync::RwLock;

use anyhow::Result;
use capsule::net::MacAddr;
use serde::Deserialize;
use signatory::ed25519::{SigningKey, VerifyingKey, ALGORITHM_ID};
use signatory::pkcs8::{FromPrivateKey, PrivateKeyInfo};

use crate::certificates::GdpMeta;
use crate::kvs::GdpName;
use crate::rib::{DynamicRoutes, Route, Routes};
use crate::Env;

#[derive(Deserialize)]
struct SerializedRoutes {
    rib: Route,
    default: Route,
}

pub trait WithBroadcast<T> {
    fn broadcast() -> T;
}

impl WithBroadcast<MacAddr> for MacAddr {
    fn broadcast() -> MacAddr {
        MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
    }
}

pub fn load_routes(env: Env) -> Result<Routes> {
    let content = fs::read_to_string(match env {
        Env::Local => "routes.toml",
        Env::Aws => "routes.toml",
        Env::Nuc => "nuc_routes.toml",
    })?;
    let serialized: SerializedRoutes = toml::from_str(&content)?;

    Ok(Routes {
        rib: serialized.rib,
        default: serialized.default,
        dynamic_routes: RwLock::new(DynamicRoutes::new()),
    })
}

pub fn gdp_name_of_index(index: u8) -> GdpName {
    let (_, verify_key) = gen_keypair_u8(index).unwrap();
    GdpMeta {
        pub_key: verify_key.to_bytes(),
    }
    .hash()
}

pub fn private_key_of_index(index: u8) -> [u8; 32] {
    gen_keypair_u8(index).unwrap().0
}

pub fn metadata_of_index(index: u8) -> GdpMeta {
    let (_, verify_key) = gen_keypair_u8(index).unwrap();
    GdpMeta {
        pub_key: verify_key.to_bytes(),
    }
}

fn gen_keypair_u8(seed: u8) -> Result<([u8; 32], VerifyingKey)> {
    let mut arr = [0u8; 32];
    arr[0] = seed; // TODO: load a u8 from the toml
    gen_keypair(&arr)
}

fn gen_keypair(seed: &[u8; 32]) -> Result<([u8; 32], VerifyingKey)> {
    let private_key = PrivateKeyInfo::new(ALGORITHM_ID, seed);
    let signing_key = SigningKey::from_pkcs8_private_key_info(private_key)?;
    let verifying_key = signing_key.verifying_key();
    Ok((seed.to_owned(), verifying_key))
}
