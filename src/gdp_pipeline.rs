use std::time::{SystemTime, UNIX_EPOCH};

use capsule::batch::{Batch, Either, Pipeline, Poll};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::PortQueue;

use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::{Gdp, GdpAction};
use crate::kvs::{FwdTableEntry, Store};
use crate::pipeline::GdpPipeline;
use crate::rib::Route;

pub fn install_gdp_pipeline(
    q: PortQueue,
    gdp_pipeline: impl GdpPipeline,
    store: Store,
    nic_name: &'_ str,
    node_addr: Option<Route>,
    debug: bool,
) -> impl Pipeline + '_ {
    Poll::new(q.clone())
        .map(|packet| packet.parse::<Ethernet>()?.parse::<Ipv4>())
        .filter(move |packet| {
            if let Some(node_addr) = node_addr {
                packet.dst() == node_addr.ip && packet.envelope().dst() == node_addr.mac
            } else {
                true
            }
        })
        .map(|packet| packet.parse::<Udp<Ipv4>>()?.parse::<DTls<Ipv4>>())
        .map(decrypt_gdp)
        .map(|packet| packet.parse::<Gdp<Ipv4>>())
        .for_each(move |_| {
            if debug {
                println!("handling packet in {}", nic_name);
            }
            Ok(())
        })
        .filter_map(|mut packet| {
            // Drop if TTL <= 1, otherwise decrement and keep forwarding
            if packet.ttl() <= 1 {
                Ok(Either::Drop(packet.reset()))
            } else {
                packet.set_ttl(packet.ttl() - 1);
                Ok(Either::Keep(packet))
            }
        })
        .for_each(move |packet| {
            // Back-cache the route for 100s to allow NACK to reflect
            store.forwarding_table.put(
                packet.src(),
                FwdTableEntry::new(
                    packet.envelope().envelope().envelope().src(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 100,
                ),
            );
            Ok(())
        })
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            gdp_pipeline,
        )
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .send(q)
}
