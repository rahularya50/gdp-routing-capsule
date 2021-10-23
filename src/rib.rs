use crate::gdp::Gdp;
use crate::kvs::Store;
use anyhow::Result;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::Mbuf;
use std::fmt::Error;
use std::net::Ipv4Addr;

// static RIB_MAC: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0xFF, 0xFF, 0x00);
const RIB_IP: Ipv4Addr = Ipv4Addr::new(10, 100, 1, 10);
const RIB_PORT: u16 = 27182;

pub fn create_rib_request(
    message: Mbuf,
    key: [u8; 32],
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    _store: Store,
) -> Result<Gdp<Ipv4>> {
    let mut message = message.push::<Ethernet>()?;
    message.set_src(src_mac);
    message.set_dst(MacAddr::new(0x02, 0x00, 0x00, 0xFF, 0xFF, 0x00));

    let mut message = message.push::<Ipv4>()?;
    message.set_src(src_ip);
    message.set_dst(RIB_IP);

    let mut message = message.push::<Udp<Ipv4>>()?;
    message.set_src_port(RIB_PORT);
    message.set_dst_port(RIB_PORT);

    let mut message = message.push::<Gdp<Ipv4>>()?;

    message.reconcile_all();

    Ok(message)
}

pub fn handle_rib_reply(packet: &Mbuf, store: Store) -> Result<()> {
    Err(anyhow::format_err!("not yet implemented"))
}

pub fn handle_rib_query(packet: &Mbuf, store: Store) -> Result<Mbuf> {
    Err(anyhow::format_err!("not yet implemented"))
}

// pub fn send_rib_request(q: &PortQueue) -> () {
//     let src_mac = q.mac_addr();
//     batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
//         .map(|packet| {
//             prep_packet(
//                 packet,
//                 src_mac,
//                 Ipv4Addr::new(10, 100, 1, 255),
//                 MacAddr::new(0x0a, 0x00, 0x27, 0x00, 0x00, 0x02),
//                 Ipv4Addr::new(10, 100, 1, 1),
//             )
//         })
//         .filter(predicate)
//         .send(q.clone())
//         .run_once();
// }
