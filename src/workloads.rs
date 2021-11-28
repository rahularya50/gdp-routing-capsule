use crate::dtls::{encrypt_gdp, DTls};
use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::kvs::{GdpName, Store};
use crate::schedule::Schedule;
use crate::startup_route_lookup;
use crate::Route;
use anyhow::{anyhow, Result};
use capsule::batch::{self, Batch, Pipeline};
use capsule::config::RuntimeConfig;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::Mbuf;
use capsule::PortQueue;
use capsule::Runtime;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio_timer::delay_for;

fn prep_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
) -> Result<Gdp<Ipv4>> {
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(src_mac);
    reply.set_dst(dst_mac);

    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(src_ip);
    reply.set_dst(dst_ip);

    let mut reply = reply.push::<Udp<Ipv4>>()?;
    reply.set_src_port(27182);
    reply.set_dst_port(27182);

    let reply = reply.push::<DTls<Ipv4>>()?;

    let mut reply = reply.push::<Gdp<Ipv4>>()?;
    reply.set_action(GdpAction::Forward);
    reply.set_dst(1);

    let message = "Initial server outgoing!".as_bytes();

    let offset = reply.payload_offset();
    reply.mbuf_mut().extend(offset, message.len())?;
    reply.mbuf_mut().write_data_slice(offset, &message)?;

    reply.reconcile_all();

    Ok(reply)
}

fn send_initial_packet(
    q: PortQueue,
    nic_name: &str,
    _store: Store,
    src_ip: Ipv4Addr,
    switch_route: Route,
) -> () {
    let src_mac = q.mac_addr();
    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |packet| prep_packet(packet, src_mac, src_ip, switch_route.mac, switch_route.ip))
        .for_each(move |packet| {
            println!(
                "Sending out one-shot packet from NIC {:?}: {:?}",
                nic_name, packet
            );
            // store.with_mut_contents(|store| {
            //     store.out_statistics.record_packet(packet);
            // });
            Ok(())
        })
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .send(q)
        .run_once();
}

pub fn dev_schedule(q: PortQueue, name: &str, store: Store) -> impl Pipeline + '_ {
    let src_ip = Ipv4Addr::new(10, 100, 1, 11);
    let switch_ip = Ipv4Addr::new(10, 100, 1, 12);
    let switch_mac = MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0x02);
    let switch_route = Route {
        ip: switch_ip,
        mac: switch_mac,
    };
    Schedule::new(name, async move {
        send_initial_packet(q.clone(), name, store, src_ip, switch_route);
        delay_for(Duration::from_millis(1000)).await;
        send_initial_packet(q.clone(), name, store, src_ip, switch_route);
    })
}

fn client_schedule(q: PortQueue, name: &str, store: Store, src_ip: Ipv4Addr) -> impl Pipeline + '_ {
    let switch_route = startup_route_lookup(2).unwrap();
    Schedule::new(name, async move {
        send_initial_packet(q.clone(), name, store, src_ip, switch_route);
        delay_for(Duration::from_millis(1000)).await;
        send_initial_packet(q.clone(), name, store, src_ip, switch_route);
    })
}

pub fn start_client_server(config: RuntimeConfig, gdp_name: GdpName) -> Result<()> {
    let store = Store::new();
    let src_route = startup_route_lookup(gdp_name).ok_or(anyhow!("Invalid client GDPName!"))?;
    Runtime::build(config)?
        .add_pipeline_to_port("eth1", move |q| {
            client_schedule(q, "client", store, src_route.ip)
        })?
        .execute()
    // store.with_mut_contents(|s| -> Result<()> {
    //     let in_label = "packets_in";
    //     let out_label = "packets_out";
    //     s.in_statistics.dump_statistics(in_label)?;
    //     s.out_statistics.dump_statistics(out_label)?;
    //     Ok(())
    // })
}
