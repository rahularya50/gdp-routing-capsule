use std::net::Ipv4Addr;

use anyhow::Result;
use capsule::batch::{Batch, Disposition, Poll};
use capsule::config::RuntimeConfig;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};

use crate::certificates::{CertDest, GdpMeta, RtCert};
use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::{Gdp, GdpAction};
use crate::hardcoded_routes::{gdp_name_of_index, metadata_of_index, private_key_of_index};
use crate::kvs::GdpName;
use crate::pipeline::GdpPipeline;
use crate::rib::send_rib_query;
use crate::ribpayload::RibQuery;
use crate::runtime::build_runtime;
use crate::{pipeline, Env};

fn incoming_sidecar_pipeline(
    gdp_name: GdpName,
    meta: GdpMeta,
    private_key: [u8; 32],
    name: &'static str,
    debug: bool,
) -> impl GdpPipeline<Udp<Ipv4>> {
    // our responsibility is to validate the certificates, strip GDP headers, and forward to the receiver
    // at this stage, incoming packets have been decrypted and spurious packets discarded
    pipeline!(
        GdpAction::Forward => |group| {
            group
        }
    )
}

fn outgoing_sidecar_pipeline(
    gdp_name: GdpName,
    meta: GdpMeta,
    private_key: [u8; 32],
    name: &'static str,
    switch_ip: Ipv4Addr,
    debug: bool,
) -> impl GdpPipeline<Udp<Ipv4>> {
    // our responsibility is to set up the certificates and forward to the switch
    pipeline!(
        GdpAction::Forward => |group| {
            group
        }
    )
}

pub fn start_sidecar_listener(
    config: RuntimeConfig,
    node_addr: Ipv4Addr,
    switch_addr: Ipv4Addr,
    nic_name: &'static str,
    listen_port: u16,
    debug: bool,
    env: Env,
) -> Result<()> {
    build_runtime(config, env)?
        .add_pipeline_to_port("eth1", move |q| {
            let gdp_name = gdp_name_of_index(1);
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
                nic_name,
            );

            let incoming_pipeline =
                incoming_sidecar_pipeline(gdp_name, meta, private_key, nic_name, debug);

            let outgoing_pipeline = outgoing_sidecar_pipeline(
                gdp_name,
                meta,
                private_key,
                nic_name,
                switch_addr,
                debug,
            );

            Poll::new(q.clone())
                .map(|packet| packet.parse::<Ethernet>()?.parse::<Ipv4>())
                .filter(move |packet| packet.dst() == node_addr)
                .map(|packet| packet.parse::<Udp<Ipv4>>())
                .group_by(
                    move |packet| packet.dst_port() == listen_port,
                    pipeline! {
                            true => |group| {
                                group
                                    .map(|packet: Udp<Ipv4>| packet.parse::<Gdp<Udp<Ipv4>>>())
                                    .for_each(move |packet| {
                                        if debug {
                                            println!(
                                                "handling packet in {} (src: {:?}, dst: {:?}, type: {:?})",
                                                nic_name,
                                                packet.envelope().envelope().src(),
                                                packet.envelope().envelope().dst(),
                                                packet.action()?
                                            );
                                        }
                                        Ok(())
                                    })
                                    .group_by(
                                        |packet| packet.action().unwrap_or(GdpAction::Noop),
                                        outgoing_pipeline,
                                    )
                                    .map(|packet| Ok(packet.deparse().push()?))
                                    .map(encrypt_gdp)
                                    .map(|packet| Ok(packet.deparse()))
                            }
                            false => |group| {
                                group
                                    .map(|packet| packet.parse::<DTls<Ipv4>>())
                                    .map(decrypt_gdp)
                                    .map(|packet| packet.remove())
                                    .map(|packet| packet.parse::<Gdp<Udp<Ipv4>>>())
                                    .for_each(move |packet| {
                                        if debug {
                                            println!(
                                                "handling packet in {} (src: {:?}, dst: {:?}, type: {:?})",
                                                nic_name,
                                                packet.envelope().envelope().src(),
                                                packet.envelope().envelope().dst(),
                                                packet.action()?
                                            );
                                        }
                                        Ok(())
                                    })
                                    .group_by(
                                        |packet| packet.action().unwrap_or(GdpAction::Noop),
                                        incoming_pipeline,
                                    )
                                    .map(|packet| Ok(packet.deparse()))
                            }
                        },
                )
                .inspect(move |disp| {
                    if let Disposition::Abort(err) = disp {
                        println!("Packet aborted by {} with error {}", nic_name, err);
                    }
                })
                .send(q)
        })?
        .execute()?;
    Ok(())
}
