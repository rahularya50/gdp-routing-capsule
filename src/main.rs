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

use anyhow::Result;
use capsule::batch::{Batch, Pipeline, Poll};
use capsule::config::load_config;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::{Mbuf, PortQueue, Runtime};
use tracing::{debug, Level};
use tracing_subscriber::fmt;

use crate::gdp::Gdp;

mod gdp;

fn reply_echo(packet: &Mbuf) -> Result<Gdp<Ipv4>> {
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

    reply.set_field(gdp.field());

    let payload = gdp.mbuf().read_data_slice::<u8>(gdp.payload_offset(), gdp.payload_len())?;
    let payload = unsafe { payload.as_ref() };

    let message = "This is the server: ".as_bytes();

    let offset = reply.payload_offset();
    reply.mbuf_mut().extend(offset, message.len() + payload.len())?;
    reply.mbuf_mut().write_data_slice(offset, &message)?;
    reply.mbuf_mut().write_data_slice(offset + message.len(), payload)?;

    reply.reconcile_all();

    println!("{:?}", payload);

    // reply

    Ok(reply)
}

fn install(q: PortQueue) -> impl Pipeline {
    Poll::new(q.clone()).replace(reply_echo).send(q)
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", install)?
        .execute()
}
