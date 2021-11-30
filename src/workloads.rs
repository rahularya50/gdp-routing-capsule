use crate::dtls::{encrypt_gdp, DTls};
use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::kvs::{GdpName, Store};
use crate::schedule::Schedule;
use rand::Rng;
use crate::startup_route_lookup;
use std::fs;

use crate::statistics::make_print_stats;
use crate::Route;
use serde::Deserialize;

use anyhow::{anyhow, Result};
use capsule::batch::{self, Batch, Pipeline};
use capsule::config::RuntimeConfig;
use capsule::net::MacAddr;
use crate::dump_history;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::Mbuf;
use capsule::PortQueue;
use capsule::Runtime;

use std::net::Ipv4Addr;

use std::time::Duration;
use tokio_timer::delay_for;

const MSG: &[u8] = &[b'A'; 10000];

#[derive(Clone, Copy, Deserialize)]
pub struct TestConfig {
    pub payload_size: usize,
    pub random_dest_chance: f32,
}

pub fn load_test_config() -> Result<TestConfig> {
    let content = fs::read_to_string("test.toml")?;
    let test_config: TestConfig = toml::from_str(&content)?;

    Ok(test_config)
}

fn prep_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    payload_size: usize,
    random_dest_chance: f32,
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

    let mut rng = rand::thread_rng();
    let rval: f32 = rng.gen();
    if rval < random_dest_chance {
        reply.set_dst(rng.gen());
    } else {
        reply.set_dst(3);
    }

    let message = MSG;

    let offset = reply.payload_offset();
    reply.mbuf_mut().extend(offset, payload_size)?;
    reply.mbuf_mut().write_data_slice(offset, &message[..payload_size])?;

    reply.reconcile_all();

    Ok(reply)
}

fn send_initial_packets(
    q: PortQueue,
    _nic_name: &str,
    _store: Store,
    src_ip: Ipv4Addr,
    switch_route: Route,
    num_packets: usize,
    payload_size: usize,
    random_dest_chance: f32
) -> () {
    let src_mac = q.mac_addr();
    batch::poll_fn(|| Mbuf::alloc_bulk(num_packets).unwrap())
        .map(move |packet| prep_packet(packet, src_mac, src_ip, switch_route.mac, switch_route.ip, payload_size, random_dest_chance))
        .for_each(move |_packet| {
            //println!(
            //    "Sending out one-shot packet from NIC {:?}: {:?}",
            //    nic_name, packet
            //);
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

fn send_initial_packet(
    q: PortQueue,
    nic_name: &str,
    store: Store,
    src_ip: Ipv4Addr,
    switch_route: Route,
) {
    send_initial_packets(q, nic_name, store, src_ip, switch_route, 1, 800,0.0);
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

fn flood_single(q: PortQueue, name: &str, store: Store, src_ip: Ipv4Addr) -> impl Pipeline + '_ {
    let switch_route = startup_route_lookup(2).unwrap();
    let test_conf = load_test_config().unwrap_or_else(|_| TestConfig{payload_size: 800, random_dest_chance: 0.0});
    let payload_size = test_conf.payload_size;
    let random_dest_chance = test_conf.random_dest_chance;
    println!("Running test {} with payload size {}, random dest chance {}", "flood_single", payload_size, random_dest_chance);
    Schedule::new(name, async move {
        for _i in 0..100000 {
            send_initial_packets(q.clone(), name, store, src_ip, switch_route, 36, payload_size, random_dest_chance);
            delay_for(Duration::from_micros(1));
        }
    })
}

pub fn start_client_server(config: RuntimeConfig, gdp_name: GdpName) -> Result<()> {
    let store = Store::new();
    let (print_stats, history_map) = make_print_stats();
    let src_route = startup_route_lookup(gdp_name).ok_or(anyhow!("Invalid client GDPName!"))?;
    Runtime::build(config)?
        .add_pipeline_to_port("eth1", move |q| flood_single(q, "client", store, src_route.ip))?
        .add_periodic_task_to_core(
            0,
            print_stats,
            Duration::from_secs(1),
        )?
        .execute()?;
   
    let x = dump_history(&(*history_map.lock().unwrap())); x
}
