use std::net::Ipv4Addr;
use std::sync::RwLock;

use anyhow::{anyhow, Context, Result};
use capsule::batch::{Batch, Disposition, Poll};
use capsule::config::RuntimeConfig;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::{Mbuf, PortQueue};
use gdp_client::{
    ClientCommand, ClientCommands, ClientResponse, ClientResponses, GdpAction, GdpName,
};
use tracing::warn;

use crate::certificates::{check_packet_certificates, CertDest, GdpMeta, RtCert};
use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::{CertificateBlock, Gdp};
use crate::gdpbatch::GdpBatch;
use crate::hardcoded_routes::{
    gdp_name_of_index, metadata_of_index, private_key_of_index, WithBroadcast,
};
use crate::kvs::{SharedStore, Store};
use crate::packet_logging::{LogArrive, LogFail};
use crate::packet_ops::{get_payload, set_payload};
use crate::rib::{create_rib_request, send_rib_query};
use crate::ribpayload::RibQuery;
use crate::runtime::build_runtime;
use crate::switch::{bounce_gdp, forward_gdp};
use crate::{pipeline, Env};

fn execute_command(
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    command: &ClientCommand,
    state: &SidecarState,
) -> ClientResponse<'static> {
    match command {
        ClientCommand::SetPort { port } => match state.listen_addr.write() {
            Ok(mut listen_addr) => {
                *listen_addr = (src_mac, src_ip, *port);
                ClientResponse::PortSet { port: *port }
            }
            Err(_) => ClientResponse::Error {
                msg: "port setting failed (unable to acquire lock)".into(),
            },
        },
    }
}

struct SidecarState {
    listen_addr: RwLock<(MacAddr, Ipv4Addr, u16)>,
}

fn incoming_sidecar_pipeline(
    q: PortQueue,
    node_addr: Ipv4Addr,
    switch_ip: Ipv4Addr,
    gdp_name: GdpName,
    name: &'static str,
    state: &'static SidecarState,
    store: Store,
    debug: bool,
) -> impl Batch {
    // our responsibility is to validate the certificates, strip GDP headers, and forward to the receiver
    // at this stage, incoming packets have been decrypted and spurious packets discarded
    Poll::new(q.clone())
        .map(|packet| packet.parse::<Ethernet>()?.parse::<Ipv4>())
        .filter(move |packet| packet.dst() == node_addr)
        .map(|packet| packet.parse::<Udp<Ipv4>>())
        .map(|packet| packet.parse::<DTls<Ipv4>>())
        .map(decrypt_gdp)
        .map(|packet| packet.parse::<Gdp<DTls<Ipv4>>>())
        .logarrive(name, "incoming", debug)
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            pipeline! {
                GdpAction::Forward => |group| {
                    group
                        .group_by(move |packet| {
                            check_packet_certificates(
                                gdp_name, packet, &store, None, name, debug,
                            )
                        },
                        pipeline! {
                            true => |group| {
                                // certificates look good, redirect to listener
                                group.map(|mut packet| {
                                    let (mac, ip, port) = *state
                                        .listen_addr
                                        .read()
                                        .map_err(|_| anyhow!("failed to unlock listen addr"))?;

                                    let udp = packet.envelope_mut().envelope_mut();
                                    udp.set_dst_ip(ip.into())?;
                                    udp.set_dst_port(port);

                                    let ethernet = udp.envelope_mut().envelope_mut();
                                    ethernet.set_dst(mac);

                                    Ok(packet)
                                })
                            },
                            false => |group| {
                                // certificates not verified, query RIB for missing data
                                group
                                    .inject(move |packet| {
                                        let src_ip = packet.envelope().envelope().envelope().dst();
                                        let src_mac = packet.envelope().envelope().envelope().envelope().dst();
                                        let mut unknown_names = Vec::new();
                                        check_packet_certificates(gdp_name, packet, &store, Some(&mut unknown_names), name, debug);
                                        if debug {
                                            println!("{} querying RIB for metas {:?}", name, packet.dst());
                                        }
                                        create_rib_request(Mbuf::new()?, &RibQuery::metas_for(&unknown_names), src_mac, src_ip, switch_ip)
                                    })
                                    .map(bounce_gdp)
                                    .emit(q)
                            }
                        })
                },
            },
        )
        .map(|packet| Ok(packet.deparse()))
}

fn outgoing_sidecar_pipeline(
    q: PortQueue,
    gdp_name: GdpName,
    meta: GdpMeta,
    private_key: [u8; 32],
    name: &'static str,
    node_ip: Ipv4Addr,
    node_mac: MacAddr,
    switch_ip: Ipv4Addr,
    state: &'static SidecarState,
    debug: bool,
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

    Poll::new(q.clone())
        .map(|packet| packet.parse::<Ethernet>())
        .inspect(move |disp| {
            if debug {
                if let Disposition::Act(p) = disp {
                    warn!(?p)
                }
            }
        })
        .map(|packet| packet.parse::<Ipv4>())
        .map(|packet| packet.parse::<Udp<Ipv4>>())
        .map(|packet| packet.push::<DTls<Ipv4>>())
        .map(|packet| packet.parse::<Gdp<DTls<Ipv4>>>())
        .logarrive(name, "outgoing", debug)
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            pipeline! {
                GdpAction::Forward => |group| {
                    group
                        .map(move |mut packet| {
                            packet.set_src(gdp_name);
                            packet.set_certs(&certificates)?;
                            Ok(packet)
                        })
                        .filter_map(move |mut packet| {
                            // pretend we were received by the public NIC, so we can forward with the proper outgoing IP + MAC
                            let ipv4 = packet.envelope_mut().envelope_mut().envelope_mut();
                            ipv4.set_dst(node_ip);
                            ipv4.envelope_mut().set_dst(node_mac);
                            forward_gdp(packet, switch_ip)
                        })
                },
                GdpAction::Control => |group| {
                    group
                        .map(move |mut packet| {
                            // run commands
                            let ClientCommands { messages } = bincode::deserialize(
                                get_payload(&packet).context("failed to extract packet payload")?,
                            )
                            .context("failed to deserialize payload into commands")?;
                            let response = bincode::serialize(&ClientResponses {
                                messages: messages
                                    .iter()
                                    .map(|msg| {
                                        execute_command(
                                            packet.envelope().envelope().envelope().envelope().src(),
                                            packet.envelope().envelope().envelope().src(),
                                            msg,
                                            state,
                                        )
                                    })
                                    .collect(),
                            })?;
                            set_payload(&mut packet, &response)?;
                            Ok(packet)
                        })
                        .map(bounce_gdp)
                        .emit(q) // send out of TAP, not bound NIC
                },
            },
        )
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
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

    let state: &SidecarState = Box::leak(Box::new(SidecarState {
        listen_addr: RwLock::new((MacAddr::broadcast(), Ipv4Addr::UNSPECIFIED, 31415)),
    }));

    let store = SharedStore::new();

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
            incoming_sidecar_pipeline(
                q["eth1"].clone(),
                node_addr,
                switch_addr,
                gdp_name,
                nic_name,
                state,
                store.sync(),
                debug,
            )
            .logfail(nic_name, "incoming", debug)
            .send(q["loc"].clone())
        })?
        .add_pipeline_to_core(0, move |q| {
            outgoing_sidecar_pipeline(
                q["loc"].clone(),
                gdp_name,
                meta,
                private_key,
                nic_name,
                node_addr,
                q["eth1"].mac_addr(),
                switch_addr,
                state,
                debug,
            )
            .logfail(nic_name, "outgoing", debug)
            .send(q["eth1"].clone())
        })?
        .execute()?;
    Ok(())
}
