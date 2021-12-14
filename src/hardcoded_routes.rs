use std::collections::HashMap;
use std::fs;
use std::sync::RwLock;

use anyhow::Result;
use serde::Deserialize;
use signatory::ed25519::{SigningKey, VerifyingKey, ALGORITHM_ID};
use signatory::pkcs8::{FromPrivateKey, PrivateKeyInfo};

use crate::certificates::GdpMeta;
use crate::kvs::GdpName;
use crate::rib::{DynamicRoutes, Route, Routes};

#[derive(Deserialize)]
struct SerializedRoutes {
    routes: HashMap<String, Route>,
    rib: Route,
    default: Route,
}

pub fn startup_route_lookup(index: u8) -> Option<Route> {
    // FIXME: this is an awful hack, we shouldn't need to read the RIB to get our IP addr!
    let gdp_name = gdp_name_of_index(index);
    load_routes()
        .ok()?
        .routes
        .get(&gdp_name)
        .map(|route| route.to_owned())
}

pub fn load_routes() -> Result<Routes> {
    let content = fs::read_to_string("routes.toml")?;
    let serialized: SerializedRoutes = toml::from_str(&content)?;

    Ok(Routes {
        routes: serialized
            .routes
            .iter()
            .map(|it| -> (GdpName, Route) {
                let index = it.0.parse::<u8>().unwrap();
                let route = it.1.to_owned();
                (gdp_name_of_index(index), route)
            })
            .collect(),
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

pub fn private_key_of_index(index: u8) -> SigningKey {
    gen_keypair_u8(index).unwrap().0
}

pub fn metadata_of_index(index: u8) -> GdpMeta {
    let (_, verify_key) = gen_keypair_u8(index).unwrap();
    GdpMeta {
        pub_key: verify_key.to_bytes(),
    }
}

fn gen_keypair_u8(seed: u8) -> Result<(SigningKey, VerifyingKey)> {
    let mut arr = [0u8; 32];
    arr[0] = seed; // TODO: load a u8 from the toml
    gen_keypair(&arr)
}

fn gen_keypair(seed: &[u8; 32]) -> Result<(SigningKey, VerifyingKey)> {
    let signing_key =
        SigningKey::from_pkcs8_private_key_info(PrivateKeyInfo::new(ALGORITHM_ID, seed))?;
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}
