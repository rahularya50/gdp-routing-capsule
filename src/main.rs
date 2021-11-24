use std::net::Ipv4Addr;

/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/
use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::gdpbatch::GdpBatch;
use crate::kvs::Store;
use crate::pipeline::GdpPipeline;
use crate::rib::create_rib_request;
use crate::rib::handle_rib_query;
use crate::rib::handle_rib_reply;
use crate::rib::test_signatures;
use anyhow::anyhow;
use anyhow::Result;
use std::io;
use std::thread;

use capsule::batch::{self, Batch, Pipeline, Poll};
use capsule::config::load_config;

use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::Mbuf;
use capsule::{PortQueue, Runtime};
use tracing::Level;
use tracing_subscriber::fmt;

use std::sync::Arc;

mod dtls;
mod gdp;
mod gdpbatch;
mod inject;
mod kvs;
mod pipeline;
mod rib;
mod statistics;

fn find_destination(gdp: &Gdp<Ipv4>, store: Store) -> Option<Ipv4Addr> {
    store.with_contents(|store| store.forwarding_table.get(&gdp.dst()).cloned())
}

fn bounce_udp(udp: &mut Udp<Ipv4>) -> &mut Udp<Ipv4> {
    let udp_src_port = udp.dst_port();
    let udp_dst_port = udp.src_port();
    udp.set_src_port(udp_src_port);
    udp.set_dst_port(udp_dst_port);

    let ethernet = udp.envelope_mut();
    let eth_src = ethernet.dst();
    let eth_dst = ethernet.src();
    ethernet.set_src(eth_src);
    ethernet.set_dst(eth_dst);

    udp
}

fn forward_gdp(mut gdp: Gdp<Ipv4>, dst: Ipv4Addr) -> Result<Gdp<Ipv4>> {
    let dtls = gdp.envelope_mut();
    let udp = dtls.envelope_mut();
    let ipv4 = udp.envelope_mut();

    ipv4.set_src(ipv4.dst());
    ipv4.set_dst(dst);

    Ok(gdp)
}

fn bounce_gdp(mut gdp: Gdp<Ipv4>) -> Result<Gdp<Ipv4>> {
    gdp.remove_payload()?;
    gdp.set_action(GdpAction::Nack);
    bounce_udp(gdp.envelope_mut().envelope_mut());
    gdp.reconcile_all();
    Ok(gdp)
}

fn switch_pipeline(_q: PortQueue, store: Store) -> impl GdpPipeline {
    return pipeline! {
        GdpAction::Forward => |group| {
            group.group_by(
                move |packet| find_destination(packet, store).is_some(),
                pipeline! {
                    true => |group| {
                        group.map(move |packet| {
                            let dst = find_destination(&packet, store).ok_or(anyhow!("can't find the destination"))?;
                            forward_gdp(packet, dst)
                        })
                    }
                    false => |group| {
                        group
                        .map(bounce_gdp)
                        .inject(move |packet| {
                            let src_ip = packet.envelope().envelope().envelope().src();
                            let src_mac = packet.envelope().envelope().envelope().envelope().dst();
                            println!("Querying RIB for destination {:?}", packet.dst());
                            create_rib_request(Mbuf::new()?, packet.dst(), src_mac, src_ip, store)
                        })
                    }
                })
        }
        GdpAction::RibReply => |group| {
            group.for_each(move |packet| handle_rib_reply(packet, store))
                .filter(|_| false)
        }
        _ => |group| {group.filter(|_| false)}
    };
}

fn rib_pipeline(_q: PortQueue, store: Store) -> impl GdpPipeline {
    return pipeline! {
        GdpAction::RibGet => |group| {
            group.replace(move |packet| handle_rib_query(packet, store))
        }
        _ => |group| {group.filter(|_| false)}
    };
}

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
    reply.set_dst(5);

    let message = "Initial server outgoing!".as_bytes();

    let offset = reply.payload_offset();
    reply.mbuf_mut().extend(offset, message.len())?;
    reply.mbuf_mut().write_data_slice(offset, &message)?;

    reply.reconcile_all();

    Ok(reply)
}

fn send_initial_packet(q: PortQueue, nic_name: &str, store: Store) -> () {
    let src_mac = q.mac_addr();
    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |packet| {
            prep_packet(
                packet,
                src_mac,
                Ipv4Addr::new(10, 100, 1, 11),
                MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0x02),
                Ipv4Addr::new(10, 100, 1, 12),
            )
        })
        .for_each(move |packet| {
            println!(
                "Sending out one-shot packet from NIC {:?}: {:?}",
                nic_name, packet
            );
            store.with_mut_contents(|store| {
                store.out_statistics.record_packet(packet);
            });
            Ok(())
        })
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .send(q)
        .run_once();
}

fn install_gdp_pipeline<T: GdpPipeline>(
    q: PortQueue,
    gdp_pipeline: T,
    store: Store,
    nic_name: &str,
) -> impl Pipeline + '_ {
    let nic_name_copy = nic_name.clone();
    Poll::new(q.clone())
        .map(|packet| {
            Ok(packet
                .parse::<Ethernet>()?
                .parse::<Ipv4>()?
                .parse::<Udp<Ipv4>>()?
                .parse::<DTls<Ipv4>>()?)
        })
        .map(decrypt_gdp)
        .map(|packet| Ok(packet.parse::<Gdp<Ipv4>>()?))
        .for_each(move |packet| {
            // Back-cache the route to allow NACK to reflect
            store.with_mut_contents(|store| {
                store
                    .forwarding_table
                    .insert(packet.src(), packet.envelope().envelope().envelope().src());
            });
            println!("Parsed gdp packet in NIC {:?}: {:?}", nic_name_copy, packet);

            // Record incoming packet statistics
            store.with_mut_contents(|store| {
                store.in_statistics.record_packet(packet);
            });
            Ok(())
        })
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            gdp_pipeline,
        )
        .for_each(move |packet| {
            println!("Sent gdp packet in NIC {:?}: {:?}", nic_name_copy, packet);

            // Record outgoing packet statistics
            store.with_mut_contents(|store| {
                store.out_statistics.record_packet(packet);
            });
            Ok(())
        })
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .send(q)
}

fn main() -> Result<()> {
    test_signatures(b"go bears").unwrap();

    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;

    let store1 = Store::new();
    let store2 = Store::new();
    let store3 = Store::new();

    let name1 = "rib1";
    let name2 = "sw1";
    let name3 = "sw2";

    // Command handling thread
    thread::spawn(move || loop {
        let mut buffer = String::new();
        let _ = io::stdin().read_line(&mut buffer);
        buffer.pop(); // erase newline
        println!("Received command {:?}", buffer);
        if buffer == "dump" {
            println!("Dumping statistics to file");
            store2.with_mut_contents(|s| {
                let in_label = "store2_in";
                let out_label = "store2_out";
                let _ = s.in_statistics.dump_statistics(in_label);
                let _ = s.out_statistics.dump_statistics(out_label);
            });
            store3.with_mut_contents(|s| {
                let in_label = "store3_in";
                let out_label = "store3_out";
                let _ = s.in_statistics.dump_statistics(in_label);
                let _ = s.out_statistics.dump_statistics(out_label);
            });
        }
    });

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", move |q| {
            install_gdp_pipeline(q.clone(), rib_pipeline(q.clone(), store1), store1, name1)
        })?
        .add_pipeline_to_port("eth2", move |q| {
            send_initial_packet(q.clone(), name2, store2);
            install_gdp_pipeline(q.clone(), switch_pipeline(q.clone(), store2), store2, name2)
        })?
        .add_pipeline_to_port("eth3", move |q| {
            install_gdp_pipeline(q.clone(), switch_pipeline(q.clone(), store3), store3, name3)
        })?
        .execute()
}
