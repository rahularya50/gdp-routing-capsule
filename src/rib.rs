use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::kvs::GdpName;
use crate::kvs::Store;
use anyhow::Result;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::Mbuf;
use std::net::Ipv4Addr;

// static RIB_MAC: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0xFF, 0xFF, 0x00);
const RIB_IP: Ipv4Addr = Ipv4Addr::new(10, 100, 1, 10);
const RIB_PORT: u16 = 27182;

pub fn create_rib_request(
    message: Mbuf,
    key: GdpName,
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

    message.set_action(GdpAction::RibGet);
    message.set_key(key);

    message.reconcile_all();

    Ok(message)
}

pub fn handle_rib_reply(packet: &Gdp<Ipv4>, store: Store) -> Result<()> {
    store.with_mut_contents(|store| {
        store
            .forwarding_table
            .insert(packet.key(), packet.value().into())
    });
    Ok(())
}

pub fn handle_rib_query(packet: &Gdp<Ipv4>, _store: Store) -> Result<Gdp<Ipv4>> {
    let udp = packet.envelope();
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

    let mut out = out.push::<Gdp<Ipv4>>()?;
    out.set_action(GdpAction::RibReply);
    out.set_key(packet.key());
    out.set_value(10 /* fixme */);

    out.reconcile_all();
    Ok(out)
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
