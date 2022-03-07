use std::net::Ipv4Addr;

use capsule::batch::{Batch, Disposition, Either, Pipeline, Poll};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::PortQueue;

use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::{Gdp, GdpAction};
use crate::pipeline::GdpPipeline;


pub fn install_gdp_pipeline(
    q: PortQueue,
    gdp_pipeline: impl GdpPipeline,
    nic_name: &'_ str,
    node_addr: Ipv4Addr,
    debug: bool,
) -> impl Pipeline + '_ {
    Poll::new(q.clone())
        .map(|packet| packet.parse::<Ethernet>()?.parse::<Ipv4>())
        .filter(move |packet| packet.dst() == node_addr)
        .map(|packet| packet.parse::<Udp<Ipv4>>()?.parse::<DTls<Ipv4>>())
        .map(decrypt_gdp)
        .map(|packet| packet.parse::<Gdp<Ipv4>>())
        .for_each(move |packet| {
            if debug {
                println!(
                    "handling packet in {} (src: {:?}, dst: {:?}, type: {:?})",
                    nic_name,
                    packet.envelope().envelope().envelope().src(),
                    packet.envelope().envelope().envelope().dst(),
                    packet.action()?
                );
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
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            gdp_pipeline,
        )
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .inspect(move |disp| {
            if let Disposition::Abort(err) = disp {
                println!("Packet aborted by {} with error {}", nic_name, err);
            }
        })
        .send(q)
}
