use std::borrow::Cow;
use std::collections::HashMap;
use std::iter::empty;

use anyhow::{anyhow, Result};
use gdp_client::GdpName;
use serde::{Deserialize, Serialize};

use crate::certificates::{CertContents, CertDest, Certificate, GdpMeta, RtCert};
use crate::kvs::Store;
use crate::rib::{DynamicRoutes, Routes};
use crate::FwdTableEntry;

#[derive(Deserialize, Serialize)]
pub struct RibQuery {
    pub metas_for_names: Vec<GdpName>,
    pub ips_for_names: Vec<GdpName>,
    pub next_hop_for_names: Vec<GdpName>,
    pub new_nodes: Vec<GdpMeta>,
    pub new_certs: Vec<Certificate>,
}

impl RibQuery {
    pub fn next_hop_for(dst: GdpName) -> Self {
        RibQuery {
            metas_for_names: Vec::new(),
            ips_for_names: vec![dst],
            next_hop_for_names: vec![dst],
            new_nodes: Vec::new(),
            new_certs: Vec::new(),
        }
    }

    pub fn metas_for(names: &[GdpName]) -> Self {
        RibQuery {
            metas_for_names: names.to_owned(),
            ips_for_names: Vec::new(),
            next_hop_for_names: Vec::new(),
            new_nodes: Vec::new(),
            new_certs: Vec::new(),
        }
    }

    pub fn announce_route(meta: GdpMeta, cert: Certificate) -> Self {
        Self::announce_routes(meta, vec![cert].into())
    }

    pub fn announce_routes(meta: GdpMeta, certs: Cow<[Certificate]>) -> Self {
        RibQuery {
            metas_for_names: Vec::new(),
            ips_for_names: Vec::new(),
            next_hop_for_names: Vec::new(),
            new_nodes: vec![meta],
            new_certs: certs.into_owned(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RibResponse {
    pub metas: Vec<GdpMeta>,
    pub certs: Vec<Certificate>,
}

fn insert_cert(cert: Certificate, routes: &mut DynamicRoutes) -> Result<()> {
    let gdp_name = cert.contents.owner();
    let gdp_metadata = routes
        .metadata
        .get(gdp_name)
        .ok_or_else(|| anyhow!("unknown gdpname owning cert"))?;
    cert.verify(gdp_metadata)?;
    match cert.contents {
        CertContents::RtCert(RtCert { ref proxy, .. }) => match proxy {
            CertDest::GdpName(_dest) => {
                println!("RIB recording delegation");
                routes.next_hop.insert(*gdp_name, cert);
            }
            CertDest::IpAddr(dest) => {
                println!("RIB recording node at {:?}", dest);
                routes.locations.insert(*gdp_name, cert);
            }
        },
    }
    Ok(())
}

fn key_lookup<'a, T: Clone>(
    name_iter: impl Iterator<Item = &'a GdpName> + 'a,
    lookup: &'a HashMap<GdpName, T>,
    debug: bool,
) -> impl Iterator<Item = T> + 'a {
    name_iter.filter_map(move |gdp_name| {
        if debug {
            println!(
                "Looking up {:?} in RIB (found={:?})",
                gdp_name,
                lookup.contains_key(gdp_name)
            )
        }
        lookup.get(gdp_name).cloned()
    })
}

pub fn generate_rib_response(query: RibQuery, routes: &Routes, debug: bool) -> RibResponse {
    for meta in query.new_nodes {
        routes
            .dynamic_routes
            .write()
            .unwrap()
            .metadata
            .insert(meta.hash(), meta);
    }
    for cert in query.new_certs {
        let _ = insert_cert(cert, &mut routes.dynamic_routes.write().unwrap());
    }
    let dynamic_routes = routes.dynamic_routes.read().unwrap();

    let certs = empty()
        .chain(key_lookup(
            query.ips_for_names.iter(),
            &dynamic_routes.locations,
            debug,
        ))
        .chain(key_lookup(
            query.next_hop_for_names.iter(),
            &dynamic_routes.next_hop,
            debug,
        ))
        .collect::<Vec<_>>();

    let metas = empty()
        .chain(key_lookup(
            query.metas_for_names.iter(),
            &dynamic_routes.metadata,
            debug,
        ))
        .chain(key_lookup(
            certs.iter().map(|cert| cert.contents.owner()),
            &dynamic_routes.metadata,
            debug,
        ))
        .collect();

    RibResponse { metas, certs }
}

pub fn process_rib_response(response: RibResponse, store: Store, debug: bool) -> Result<()> {
    if debug {
        println!("{:?}", response);
    }
    process_rib_data(&response.metas, &response.certs, None, store, debug)
}

pub fn process_rib_data<'a>(
    metas: &[GdpMeta],
    certs: &'a [Certificate],
    mut out_certs: Option<&mut Vec<&'a Certificate>>,
    store: Store,
    debug: bool,
) -> Result<()> {
    for meta in metas {
        store.gdp_metadata.put(meta.hash(), *meta);
    }
    for cert in certs {
        let owner = cert.contents.owner();
        let meta = store.gdp_metadata.get_unchecked(owner);
        if let Some(meta) = meta {
            cert.verify(&meta)?;
            match &cert.contents {
                CertContents::RtCert(RtCert {
                    base,
                    proxy,
                    expiration_time,
                    ..
                }) => match proxy {
                    CertDest::GdpName(gdp_name) => {
                        store.next_hops.put(
                            *base,
                            FwdTableEntry {
                                val: *gdp_name,
                                expiration_time: *expiration_time,
                            },
                        );
                        if let Some(ref mut out_certs) = out_certs {
                            out_certs.push(cert);
                        }
                    }
                    CertDest::IpAddr(ip_addr) => {
                        if debug {
                            println!("Inserting mapping in switch to {:?}", ip_addr);
                        }
                        store
                            .forwarding_table
                            .put(*base, FwdTableEntry::new(*ip_addr, *expiration_time))
                    }
                },
            }
        }
    }
    Ok(())
}
