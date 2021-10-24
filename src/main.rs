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
#![feature(trait_alias)]
use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::kvs::Store;
use crate::rib::handle_rib_query;
use crate::rib::handle_rib_reply;
use anyhow::Result;
use capsule::batch::Bridge;
use capsule::batch::{Batch, Pipeline, Poll};
use capsule::compose;
use capsule::config::load_config;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::{Mbuf, PortQueue, Runtime};
use strum::IntoEnumIterator;
use tracing::{debug, Level};
use tracing_subscriber::fmt;

mod gdp;
mod kvs;
mod rib;

fn try_forward_gdp(packet: &Mbuf, store: Store) -> Result<Mbuf> {
    let ethernet = packet.peek::<Ethernet>()?;
    let ipv4 = ethernet.peek::<Ipv4>()?;
    let udp = ipv4.peek::<Udp<Ipv4>>()?;
    let gdp = udp.peek::<Gdp<Ipv4>>()?;

    let payload = gdp
        .mbuf()
        .read_data_slice::<u8>(gdp.payload_offset(), gdp.payload_len())?;
    let payload = unsafe { payload.as_ref() };

    // Construct reply
    let reply = Mbuf::new()?;
    // Ethernet-frame level
    let mut reply = reply.push::<Ethernet>()?;

    // IP Layer
    let mut reply = reply.push::<Ipv4>()?;
    reply.set_ttl(150);

    let mut reply = reply.push::<Udp<Ipv4>>()?;
    reply.set_src_port(udp.dst_port());
    reply.set_dst_port(udp.src_port());

    let mut reply = reply.push::<Gdp<Ipv4>>()?;

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

    Ok(reply.deparse().deparse().deparse().deparse())
}

fn get_gdp_action(packet: &Mbuf) -> GdpAction {
    (|packet: &Mbuf| {
        packet
            .peek::<Ethernet>()?
            .peek::<Ipv4>()?
            .peek::<Udp<Ipv4>>()?
            .peek::<Gdp<Ipv4>>()?
            .action()
    })(packet)
    .unwrap_or(GdpAction::Noop)
}

trait GdpPipeline = Fn(GdpAction, Bridge<Mbuf>) -> Box<dyn Batch<Item = Mbuf>> + Copy + 'static;

fn switch_pipeline(store: Store) -> impl GdpPipeline {
    return move |action, group: Bridge<Mbuf>| match action {
        GdpAction::Get => Box::new(group.map(move |packet| try_forward_gdp(&packet, store))) as _,
        GdpAction::RibReply => Box::new(
            group
                .for_each(move |packet| handle_rib_reply(&packet, store))
                .filter(|_| false),
        ) as _,
        _ => Box::new(group.filter(|_| false)) as _,
    };
}

fn rib_pipeline(store: Store) -> impl GdpPipeline {
    return move |action, group: Bridge<Mbuf>| match action {
        GdpAction::RibGet => {
            Box::new(group.replace(move |packet| handle_rib_query(&packet, store.clone()))) as _
        }
        _ => Box::new(group.filter(|_| false)) as _,
    };
}

fn install_gdp_pipeline<T: GdpPipeline>(q: PortQueue, gdp_pipeline: T) -> impl Pipeline {
    Poll::new(q.clone())
        .group_by(get_gdp_action, |groups| {
            for variant in GdpAction::iter() {
                groups.insert(
                    Some(variant),
                    Box::new(move |group| gdp_pipeline(variant, group)),
                );
            }
            groups.insert(None, Box::new(|group| Box::new(group.filter(|_| false))));
        })
        .send(q)
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;

    let store1 = Store::new();
    let store2 = Store::new();

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", move |q| {
            install_gdp_pipeline(q, switch_pipeline(store1))
        })?
        .add_pipeline_to_port("eth2", move |q| {
            install_gdp_pipeline(q, rib_pipeline(store1))
        })?
        .execute()
}
