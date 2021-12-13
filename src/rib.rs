use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use capsule::batch::Batch;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::Mbuf;
use serde::{Deserialize, Serialize};
use signatory::ed25519::{Signature, SigningKey, VerifyingKey, ALGORITHM_ID};
use signatory::pkcs8::{FromPrivateKey, PrivateKeyInfo};
use signatory::signature::{Signer, Verifier};

use crate::dtls::DTls;
use crate::gdp::{Gdp, GdpAction, GdpMeta};
use crate::kvs::{GdpName, Store};
use crate::{pipeline, FwdTableEntry, GdpPipeline};

const RIB_PORT: u16 = 27182;

pub fn create_rib_request(
    message: Mbuf,
    key: GdpName,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_route: Route,
) -> Result<Gdp<Ipv4>> {
    let mut message = message.push::<Ethernet>()?;
    message.set_src(src_mac);
    message.set_dst(dst_route.mac);

    let mut message = message.push::<Ipv4>()?;
    message.set_src(src_ip);
    message.set_dst(dst_route.ip);

    let mut message = message.push::<Udp<Ipv4>>()?;
    message.set_src_port(RIB_PORT);
    message.set_dst_port(RIB_PORT);

    let message = message.push::<DTls<Ipv4>>()?;

    let mut message = message.push::<Gdp<Ipv4>>()?;

    message.set_action(GdpAction::RibGet);

    let query = RibQuery::new(key);
    let content = bincode::serialize(&query).unwrap();
    let offset = message.payload_offset();
    message.mbuf_mut().extend(offset, content.len())?;
    message.mbuf_mut().write_data_slice(offset, &content)?;

    message.reconcile_all();
    Ok(message)
}

pub fn handle_rib_reply(packet: &Gdp<Ipv4>, store: Store) -> Result<()> {
    let data_slice = packet
        .mbuf()
        .read_data_slice(packet.payload_offset(), packet.payload_len())
        .unwrap();
    let data_slice_ref = unsafe { data_slice.as_ref() };
    let response: RibResponse = bincode::deserialize(data_slice_ref).unwrap();
    let expiration_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + response.ttl;
    store.forwarding_table.put(
        response.gdp_name,
        FwdTableEntry::new(response.ip, expiration_time),
    );

    Ok(())
}

fn handle_rib_query(
    packet: &Gdp<Ipv4>,
    nic_name: &str,
    routes: &Routes,
    use_default: bool,
    debug: bool,
) -> Result<Gdp<Ipv4>> {
    // read the query payload
    let data_slice = packet
        .mbuf()
        .read_data_slice(packet.payload_offset(), packet.payload_len())?;
    let data_slice_ref = unsafe { data_slice.as_ref() };
    let query: RibQuery = bincode::deserialize(data_slice_ref).unwrap();

    let dtls = packet.envelope();
    let udp = dtls.envelope();
    let ipv4 = udp.envelope();
    let ethernet = ipv4.envelope();

    let out = Mbuf::new()?;
    let mut out = out.push::<Ethernet>()?;
    out.set_src(ethernet.dst());
    out.set_dst(ethernet.src());

    let mut out = out.push::<Ipv4>()?;
    out.set_src(ipv4.dst());
    out.set_dst(ipv4.src());

    let mut out = out.push::<Udp<Ipv4>>()?;
    out.set_src_port(udp.dst_port());
    out.set_dst_port(udp.src_port());

    let out = out.push::<DTls<Ipv4>>()?;

    let mut out = out.push::<Gdp<Ipv4>>()?;
    out.set_action(GdpAction::RibReply);
    let mut result: Option<&GdpRoute> = routes.routes.get(&query.gdp_name);
    if result.is_none() {
        if use_default {
            result = Some(&routes.default);
        } else {
            return Err(anyhow!("GDPName not found!"));
        }
    }
    if debug {
        println!(
            "{} replying to query looking up {:?}",
            nic_name, query.gdp_name
        );
    }
    // TTL default is 4 hours
    let rib_response = RibResponse::new(query.gdp_name, result.unwrap().route.ip, 14_400);
    let message = bincode::serialize(&rib_response).unwrap();
    let offset = out.payload_offset();
    out.mbuf_mut().extend(offset, message.len())?;
    out.mbuf_mut().write_data_slice(offset, &message)?;

    out.reconcile_all();
    Ok(out)
}

pub fn rib_pipeline(
    nic_name: &'static str,
    routes: &'static Routes,
    use_default: bool,
    debug: bool,
) -> impl GdpPipeline {
    pipeline! {
        GdpAction::RibGet => |group| {
            group.replace(move |packet| handle_rib_query(packet, nic_name, routes, use_default, debug))
        }
        _ => |group| {group.filter(|_| false)}
    }
}

#[derive(Deserialize)]
struct SerializedRoutes {
    routes: HashMap<String, Route>,
    rib: Route,
    default: Route,
}

pub struct Routes {
    pub routes: HashMap<GdpName, GdpRoute>,
    pub rib: Route,
    pub default: GdpRoute,
}

#[derive(Clone, Copy, Deserialize)]
pub struct Route {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

#[derive(Clone)]
pub struct GdpRoute {
    pub route: Route,
    pub meta: GdpMeta,
    pub name: GdpName,
    pub verify_key: VerifyingKey,
}

impl GdpRoute {
    pub fn gdp_name_of_index(index: u8) -> GdpName {
        let (_, verify_key) = gen_keypair_u8(index).unwrap();
        GdpMeta {
            pub_key: verify_key.to_bytes(),
        }
        .hash()
    }
    pub fn from_serial_entry(index: u8, route: Route) -> Self {
        let (_, verify_key) = gen_keypair_u8(index).unwrap();
        let meta = GdpMeta {
            pub_key: verify_key.to_bytes(),
        };
        GdpRoute {
            meta,
            route,
            name: meta.hash(),
            verify_key,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct RibQuery {
    pub gdp_name: GdpName,
}

impl RibQuery {
    pub fn new(gdp_name: GdpName) -> Self {
        RibQuery { gdp_name }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct RibResponse {
    pub gdp_name: GdpName,
    pub ip: Ipv4Addr,
    pub ttl: u64,
}

impl RibResponse {
    pub fn new(gdp_name: GdpName, ip: Ipv4Addr, ttl: u64) -> Self {
        RibResponse { gdp_name, ip, ttl }
    }
}

pub fn load_routes() -> Result<Routes> {
    let content = fs::read_to_string("routes.toml")?;
    let serialized: SerializedRoutes = toml::from_str(&content)?;

    Ok(Routes {
        routes: serialized
            .routes
            .iter()
            .map(|it| -> (GdpName, GdpRoute) {
                let index = it.0.parse::<u8>().unwrap();
                let route = it.1.to_owned();
                let gdp_route = GdpRoute::from_serial_entry(index, route);
                (gdp_route.name, gdp_route)
            })
            .collect(),
        rib: serialized.rib,
        default: GdpRoute::from_serial_entry(u8::MAX, serialized.default),
    })
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

fn sign(key: &SigningKey, msg: &[u8]) -> Signature {
    Signature::new(key.sign(msg).to_bytes())
}

pub fn test_signatures(msg: &'_ [u8]) -> Result<&'_ [u8]> {
    let seed = [0u8; 32];
    let (sign_key, verify_key) = gen_keypair(&seed)?;
    let verify_bytes = verify_key.to_bytes();
    let verify_key = VerifyingKey::from_bytes(&verify_bytes)?;
    let sig = sign(&sign_key, msg);
    let enc_sig = sig.to_bytes();
    let dec_sig = Signature::new(enc_sig);
    verify_key.verify(msg, &dec_sig)?;
    Ok(msg)
}
