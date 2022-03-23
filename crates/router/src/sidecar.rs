use std::net::Ipv4Addr;

use anyhow::Result;
use capsule::batch::{Batch, Poll};
use capsule::config::RuntimeConfig;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::PortQueue;
use client::{GdpAction, GdpName};

use crate::certificates::{CertDest, GdpMeta, RtCert};
use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::{CertificateBlock, Gdp};
use crate::hardcoded_routes::{
    gdp_name_of_index, metadata_of_index, private_key_of_index, WithBroadcast,
};
use crate::packet_logging::LogFail;
use crate::rib::send_rib_query;
use crate::ribpayload::RibQuery;
use crate::runtime::build_runtime;
use crate::{pipeline, Env};

fn base_sidecar_pipeline(q: PortQueue, node_addr: Ipv4Addr) -> impl Batch<Item = Udp<Ipv4>> {
    Poll::new(q)
        .map(|packet| packet.parse::<Ethernet>()?.parse::<Ipv4>())
        .filter(move |packet| packet.dst() == node_addr)
        .map(|packet| packet.parse::<Udp<Ipv4>>())
}

#[allow(unused)]
fn append_incoming_sidecar_pipeline(
    batch: impl Batch<Item = Udp<Ipv4>>,
    gdp_name: GdpName,
    meta: GdpMeta,
    private_key: [u8; 32],
    name: &'static str,
    debug: bool,
) -> impl Batch {
    // our responsibility is to validate the certificates, strip GDP headers, and forward to the receiver
    // at this stage, incoming packets have been decrypted and spurious packets discarded
    batch
        .map(|packet| packet.parse::<DTls<Ipv4>>())
        .map(decrypt_gdp)
        .map(|packet| packet.remove())
        .map(|packet| packet.parse::<Gdp<Udp<Ipv4>>>())
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            pipeline!(
                GdpAction::Forward => |group| {
                    group
                }
            ),
        )
        .map(|packet| Ok(packet.deparse()))
}

fn append_outgoing_sidecar_pipeline(
    batch: impl Batch<Item = Udp<Ipv4>>,
    gdp_name: GdpName,
    meta: GdpMeta,
    private_key: [u8; 32],
    _name: &'static str,
    node_ip: Ipv4Addr,
    node_mac: MacAddr,
    switch_ip: Ipv4Addr,
    _debug: bool,
) -> impl Batch {
    // our responsibility is to set up the certificates and forward to the switch
    let certificates = vec![RtCert::new_wrapped(
        meta,
        private_key,
        CertDest::GdpName(gdp_name_of_index(2)),
        true,
    )
    .unwrap()];

    let certificates = CertificateBlock { certificates };

    batch
        .map(|packet: Udp<Ipv4>| packet.parse::<Gdp<Udp<Ipv4>>>())
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            pipeline!(
                GdpAction::Forward => |group| {
                    group
                        .map(move |mut packet: Gdp<Udp<Ipv4>>| {
                            packet.set_src(gdp_name);
                            packet.set_certs(&certificates)?;
                            Ok(packet)
                        })
                        .map(move |mut packet| {
                            let udp = packet.envelope_mut();
                            let ipv4 = udp.envelope_mut();
                            ipv4.set_src(node_ip);
                            ipv4.set_dst(switch_ip);

                            let ethernet = ipv4.envelope_mut();
                            ethernet.set_src(node_mac);
                            ethernet.set_dst(MacAddr::broadcast());
                            Ok(packet)
                        })
                }
            ),
        )
        .map(|packet| Ok(packet.deparse().push()?))
        .map(encrypt_gdp)
        .map(|packet| Ok(packet.deparse()))
}

pub fn start_sidecar_listener(
    config: RuntimeConfig,
    node_addr: Ipv4Addr,
    switch_addr: Ipv4Addr,
    nic_name: &'static str,
    debug: bool,
    env: Env,
) -> Result<()> {
    let gdp_name = gdp_name_of_index(1);
    let meta = metadata_of_index(1);
    let private_key = private_key_of_index(1);

    build_runtime(config, env)?
        .add_pipeline_to_core(0, move |q| {
            send_rib_query(
                q["eth1"].clone(),
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
                nic_name,
            );
            append_incoming_sidecar_pipeline(
                base_sidecar_pipeline(q["eth1"].clone(), node_addr),
                gdp_name,
                meta,
                private_key,
                nic_name,
                debug,
            )
            .logfail(nic_name, "incoming", debug)
            .send(q["loc"].clone())
        })?
        .add_pipeline_to_core(0, move |q| {
            append_outgoing_sidecar_pipeline(
                base_sidecar_pipeline(q["loc"].clone(), node_addr),
                gdp_name,
                meta,
                private_key,
                nic_name,
                node_addr,
                q["eth1"].mac_addr(),
                switch_addr,
                debug,
            )
            .logfail(nic_name, "outgoing", debug)
            .send(q["eth1"].clone())
        })?
        .execute()?;
    Ok(())
}
