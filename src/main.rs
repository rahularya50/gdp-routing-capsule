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

use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::kvs::Store;
use anyhow::Result;
use capsule::batch::{self, Batch, Pipeline, Poll};
use capsule::config::load_config;
use capsule::debug;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::{Mbuf, PortQueue, Runtime};
use std::net::Ipv4Addr;
use tracing::Level;
use tracing_subscriber::fmt;

mod gdp;
mod kvs;

fn parse_ipv4_gdp(packet: &Mbuf, store: Store) -> Result<Gdp<Ipv4>> {
    let reply = Mbuf::new()?;

    let ethernet = packet.peek::<Ethernet>()?;
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(ethernet.dst());
    reply.set_dst(ethernet.src());

    let ipv4 = ethernet.peek::<Ipv4>()?;
    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(ipv4.dst());
    reply.set_dst(ipv4.src());
    reply.set_ttl(150);

    let udp = ipv4.peek::<Udp<Ipv4>>()?;
    let mut reply = reply.push::<Udp<Ipv4>>()?;
    reply.set_src_port(udp.dst_port());
    reply.set_dst_port(udp.src_port());

    let gdp = udp.peek::<Gdp<Ipv4>>()?;
    let mut reply = reply.push::<Gdp<Ipv4>>()?;

    match gdp.action()? {
        GdpAction::NOOP => (),
        GdpAction::GET => {
            store
                .get(&gdp.key())
                .and_then(|value| Some(reply.set_value(value)));
        }
        GdpAction::PUT => store.put(gdp.key(), gdp.value()),
    }

    let payload = gdp
        .mbuf()
        .read_data_slice::<u8>(gdp.payload_offset(), gdp.payload_len())?;
    let payload = unsafe { payload.as_ref() };

    let message = "This is the server: ".as_bytes();

    let offset = reply.payload_offset();
    reply
        .mbuf_mut()
        .extend(offset, message.len() + payload.len())?;
    reply.mbuf_mut().write_data_slice(offset, &message)?;
    reply
        .mbuf_mut()
        .write_data_slice(offset + message.len(), payload)?;

    reply.reconcile_all();

    debug!(?reply);
    let envelope = reply.envelope();
    debug!(?envelope);
    let envelope = envelope.envelope();
    debug!(?envelope);
    let envelope = envelope.envelope();
    debug!(?envelope);

    Ok(reply)
}

fn prep_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    _store: Store,
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

    let mut reply = reply.push::<Gdp<Ipv4>>()?;

    let message = "Initial server outgoing!".as_bytes();

    let offset = reply.payload_offset();
    reply.mbuf_mut().extend(offset, message.len())?;
    reply.mbuf_mut().write_data_slice(offset, &message)?;

    reply.reconcile_all();

    debug!(?reply);
    let envelope = reply.envelope();
    debug!(?envelope);
    let envelope = envelope.envelope();
    debug!(?envelope);
    let envelope = envelope.envelope();
    debug!(?envelope);

    Ok(reply)
}

fn install_outgoing(q: &PortQueue, store: Store) -> () {
    let src_mac = q.mac_addr();
    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |packet| {
            prep_packet(
                packet,
                src_mac,
                Ipv4Addr::new(10, 100, 1, 255),
                MacAddr::new(0x0a, 0x00, 0x27, 0x00, 0x00, 0x02),
                Ipv4Addr::new(10, 100, 1, 1),
                store.clone(),
            )
        })
        .send(q.clone())
        .run_once();
}

fn install(q: PortQueue, store: Store) -> impl Pipeline {
    install_outgoing(&q, store.clone());

    Poll::new(q.clone())
        .replace(move |packet| parse_ipv4_gdp(packet, store.clone()))
        .send(q)
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;

    let store = Store::new();

    Runtime::build(config)?
        // .add_pipeline_to_port("eth1", move |q| install_outgoing(q, store.clone()))?
        .add_pipeline_to_port("eth1", move |q| install(q, store.clone()))?
        .execute()
}
