use std::fs;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use capsule::batch::{self, Batch, Pipeline};
use capsule::config::RuntimeConfig;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::{Mbuf, PortQueue};
use client::{GdpAction, GdpName};
use rand::Rng;
use serde::Deserialize;
use tokio_timer::delay_for;

use crate::certificates::{CertDest, Certificate, RtCert};
use crate::dtls::{encrypt_gdp, DTls};
use crate::gdp::{CertificateBlock, Gdp};
use crate::hardcoded_routes::{
    gdp_name_of_index, metadata_of_index, private_key_of_index, WithBroadcast,
};
use crate::rib::send_rib_query;
use crate::ribpayload::RibQuery;
use crate::runtime::build_runtime;
use crate::schedule::Schedule;
use crate::statistics::make_print_stats;
use crate::{dump_history, Env};

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
    src_gdp_name: GdpName,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    dst_gdp_name: GdpName,
    certificates: Vec<Certificate>,
    payload_size: usize,
    random_dest_chance: f32,
) -> Result<Gdp<DTls<Ipv4>>> {
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(src_mac);
    reply.set_dst(dst_mac);

    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(src_ip);
    reply.set_dst(dst_ip);

    let mut reply = reply.push::<Udp<Ipv4>>()?;
    let mut rng = rand::thread_rng();
    // randomize port to hash into different queues
    // reply.set_src_port(rng.gen());
    // reply.set_dst_port(rng.gen());
    reply.set_src_port(31415);
    reply.set_dst_port(31415);

    let reply = reply.push::<DTls<Ipv4>>()?;

    let mut reply = reply.push::<Gdp<DTls<Ipv4>>>()?;
    reply.set_action(GdpAction::Forward);

    reply.set_src(src_gdp_name);

    let rval: f32 = rng.gen();
    if rval < random_dest_chance {
        reply.set_dst(rng.gen());
    } else {
        reply.set_dst(dst_gdp_name);
    }

    reply.set_data_len(payload_size);

    let message = MSG;

    let offset = reply.payload_offset();
    reply.mbuf_mut().extend(offset, payload_size)?;
    reply
        .mbuf_mut()
        .write_data_slice(offset, &message[..payload_size])?;

    reply.set_certs(&CertificateBlock { certificates })?;

    reply.reconcile_all();

    Ok(reply)
}

fn send_initial_packets(
    q: PortQueue,
    src_ip: Ipv4Addr,
    switch_ip: Ipv4Addr,
    num_packets: usize,
    payload_size: usize,
    random_dest_chance: f32,
) {
    let src_mac = q.mac_addr();
    let src_gdp_name = gdp_name_of_index(1);
    let dst_gdp_name = gdp_name_of_index(3);
    let certificates = vec![RtCert::new_wrapped(
        metadata_of_index(1),
        private_key_of_index(1),
        CertDest::GdpName(gdp_name_of_index(2)),
        true,
    )
    .unwrap()];
    batch::poll_fn(|| Mbuf::alloc_bulk(num_packets).unwrap())
        .map(move |packet| {
            prep_packet(
                packet,
                src_mac,
                src_ip,
                src_gdp_name,
                MacAddr::broadcast(),
                switch_ip,
                dst_gdp_name,
                certificates.clone(),
                payload_size,
                random_dest_chance,
            )
        })
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .send(q)
        .run_once();
}

fn send_initial_packet(q: PortQueue, src_ip: Ipv4Addr, switch_ip: Ipv4Addr) {
    send_initial_packets(q, src_ip, switch_ip, 1, 800, 0.0);
}

pub fn dev_schedule(q: PortQueue, name: &str) -> impl Pipeline + '_ {
    let src_ip = Ipv4Addr::new(10, 100, 1, 11);
    let switch_ip = Ipv4Addr::new(10, 100, 1, 12);
    let meta = metadata_of_index(1);
    let private_key = private_key_of_index(1);
    send_rib_query(
        q.clone(),
        src_ip,
        switch_ip,
        &RibQuery::announce_route(
            meta,
            RtCert::new_wrapped(
                meta,
                private_key,
                CertDest::GdpName(gdp_name_of_index(2)),
                true,
            )
            .unwrap(),
        ),
        "client",
    );

    Schedule::new(name, async move {
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 1");
        send_initial_packet(q.clone(), src_ip, switch_ip);
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 2");
        send_initial_packet(q.clone(), src_ip, switch_ip);
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 3");
        send_initial_packet(q.clone(), src_ip, switch_ip);
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 4");
        send_initial_packet(q.clone(), src_ip, switch_ip);
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 4");
        send_initial_packet(q.clone(), src_ip, switch_ip);
    })
}

fn client_schedule(
    q: PortQueue,
    name: &str,
    src_ip: Ipv4Addr,
    switch_ip: Ipv4Addr,
) -> impl Pipeline + '_ {
    Schedule::new(name, async move {
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 1");
        send_initial_packet(q.clone(), src_ip, switch_ip);
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 2");
        send_initial_packet(q.clone(), src_ip, switch_ip);
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 3");
        send_initial_packet(q.clone(), src_ip, switch_ip);
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 4");
        send_initial_packet(q.clone(), src_ip, switch_ip);
        delay_for(Duration::from_millis(1000)).await;
        println!("sending initial packet 4");
        send_initial_packet(q.clone(), src_ip, switch_ip);
    })
}

fn flood_single(
    q: PortQueue,
    name: &str,
    src_ip: Ipv4Addr,
    switch_ip: Ipv4Addr,
) -> impl Pipeline + '_ {
    let test_conf = load_test_config().unwrap_or(TestConfig {
        payload_size: 800,
        random_dest_chance: 0.0,
    });
    let payload_size = test_conf.payload_size;
    let random_dest_chance = test_conf.random_dest_chance;
    println!(
        "Running test flood_single with payload size {}, random dest chance {}",
        payload_size, random_dest_chance
    );
    Schedule::new(name, async move {
        for _i in 0..100000 {
            send_initial_packets(
                q.clone(),
                src_ip,
                switch_ip,
                36,
                payload_size,
                random_dest_chance,
            );
            delay_for(Duration::from_micros(1));
        }
    })
}

pub fn start_client_server(
    config: RuntimeConfig,
    node_addr: Ipv4Addr,
    switch_addr: Ipv4Addr,
    env: Env,
) -> Result<()> {
    let (print_stats, history_map) = make_print_stats();

    build_runtime(config, env)?
        .add_pipeline_to_port("eth1", move |q| {
            let meta = metadata_of_index(1);
            let private_key = private_key_of_index(1);
            send_rib_query(
                q.clone(),
                node_addr,
                switch_addr,
                &RibQuery::announce_route(
                    meta,
                    RtCert::new_wrapped(
                        meta,
                        private_key,
                        CertDest::GdpName(gdp_name_of_index(2)),
                        true,
                    )
                    .unwrap(),
                ),
                "client",
            );
            client_schedule(q, "client", node_addr, switch_addr)
            // flood_single(q, "client", node_addr, switch_addr)
        })?
        .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
        .execute()?;

    dump_history(&*history_map.lock().unwrap())?;
    Ok(())
}
