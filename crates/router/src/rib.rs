use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

use anyhow::Result;
use capsule::batch::{self, Batch, Pipeline};
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::{Mbuf, PortQueue};
use client::{GdpAction, GdpName};
use serde::Deserialize;

use crate::certificates::{Certificate, GdpMeta};
use crate::dtls::{encrypt_gdp, DTls};
use crate::gdp::Gdp;
use crate::hardcoded_routes::WithBroadcast;
use crate::kvs::Store;
use crate::ribpayload::{generate_rib_response, process_rib_response, RibQuery, RibResponse};
use crate::{pipeline, GdpPipeline};

const RIB_PORT: u16 = 31415;

pub struct Routes {
    pub rib: Route,
    pub default: Route,
    pub dynamic_routes: RwLock<DynamicRoutes>,
}

pub struct DynamicRoutes {
    pub locations: HashMap<GdpName, Certificate>,
    pub next_hop: HashMap<GdpName, Certificate>,
    pub metadata: HashMap<GdpName, GdpMeta>,
}

impl DynamicRoutes {
    pub fn new() -> Self {
        Self {
            locations: HashMap::new(),
            next_hop: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
pub struct Route {
    pub ip: Ipv4Addr,
}

pub fn create_rib_request(
    message: Mbuf,
    query: &RibQuery,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Result<Gdp<DTls<Ipv4>>> {
    let mut message = message.push::<Ethernet>()?;
    message.set_src(src_mac);
    message.set_dst(MacAddr::broadcast());

    let mut message = message.push::<Ipv4>()?;
    message.set_src(src_ip);
    message.set_dst(dst_ip);

    let mut message = message.push::<Udp<Ipv4>>()?;
    message.set_src_port(RIB_PORT);
    message.set_dst_port(RIB_PORT);

    let message = message.push::<DTls<Ipv4>>()?;

    let mut message = message.push::<Gdp<DTls<Ipv4>>>()?;

    message.set_action(GdpAction::RibGet);

    let content = bincode::serialize(query).unwrap();
    let offset = message.payload_offset();
    message.mbuf_mut().extend(offset, content.len())?;
    message.mbuf_mut().write_data_slice(offset, &content)?;

    message.set_data_len(content.len());

    message.reconcile_all();
    Ok(message)
}

pub fn send_rib_query(
    q: PortQueue,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    query: &RibQuery,
    nic_name: &str,
) {
    let src_mac = q.mac_addr();
    println!("Sending initial RIB announcement from {}", nic_name);
    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |packet| create_rib_request(packet, query, src_mac, src_ip, dst_ip))
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .send(q)
        .run_once();
}

pub fn handle_rib_reply(packet: &Gdp<DTls<Ipv4>>, store: Store, debug: bool) -> Result<()> {
    let data_slice = packet
        .mbuf()
        .read_data_slice(packet.payload_offset(), packet.payload_len())?;
    let data_slice_ref = unsafe { data_slice.as_ref() };
    let response: RibResponse = bincode::deserialize(data_slice_ref)?;
    process_rib_response(response, &store, debug)?;
    Ok(())
}

fn handle_rib_query(
    packet: &Gdp<DTls<Ipv4>>,
    _nic_name: &str,
    routes: &Routes,
    _use_default: bool,
    debug: bool,
) -> Result<Gdp<DTls<Ipv4>>> {
    // read the query payload
    let data_slice = packet
        .mbuf()
        .read_data_slice(packet.payload_offset(), packet.payload_len())?;
    let data_slice_ref = unsafe { data_slice.as_ref() };
    let query: RibQuery = bincode::deserialize(data_slice_ref)?;

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

    let mut out = out.push::<Gdp<DTls<Ipv4>>>()?;
    out.set_action(GdpAction::RibReply);

    let rib_response = generate_rib_response(query, routes, debug);
    let message = bincode::serialize(&rib_response)?;
    let offset = out.payload_offset();
    out.mbuf_mut().extend(offset, message.len())?;
    out.mbuf_mut().write_data_slice(offset, &message)?;

    out.set_data_len(message.len());

    out.reconcile_all();
    Ok(out)
}

pub fn rib_pipeline(
    nic_name: &'static str,
    routes: &'static Routes,
    use_default: bool,
    debug: bool,
) -> impl GdpPipeline<DTls<Ipv4>> {
    pipeline! {
        GdpAction::RibGet => |group| {
            group.replace(move |packet| handle_rib_query(packet, nic_name, routes, use_default, debug))
        }
        _ => |group| {group.filter(|_| false)}
    }
}
