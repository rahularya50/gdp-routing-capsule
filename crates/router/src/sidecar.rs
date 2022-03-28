use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Context, Result};
use capsule::batch::{Batch, Poll};
use capsule::config::RuntimeConfig;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::{Mbuf, PortQueue};
use gdp_client::{
    ClientCommand, ClientCommands, ClientResponse, ClientResponses, GdpAction, GdpName,
};
use tokio::sync::Barrier;

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
use crate::rib::{create_rib_request, handle_rib_reply, send_rib_query, RIB_PORT};
use crate::ribpayload::RibQuery;
use crate::runtime::build_runtime;
use crate::schedule::Schedule;
use crate::switch::{bounce_gdp, bounce_udp, forward_gdp};
use crate::{pipeline, Env};

// needed since otherwise we'd be using the broadcast IP
// which may cause the reply to be dropped
const INTERNAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 18, 0, 254));

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
                                group.map(move |mut packet| {
                                    let (mac, ip, port) = *state
                                        .listen_addr
                                        .read()
                                        .map_err(|_| anyhow!("failed to unlock listen addr"))?;

                                    let udp = packet.envelope_mut().envelope_mut();
                                    udp.set_src_ip(INTERNAL_IP)?;
                                    udp.set_dst_ip(ip.into())?;
                                    udp.set_src_port(25000);
                                    udp.set_dst_port(port);

                                    let ethernet = udp.envelope_mut().envelope_mut();
                                    ethernet.set_src(mac);
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
                                        create_rib_request(Mbuf::new()?, &RibQuery::metas_for(&unknown_names), src_mac, src_ip, gdp_name, switch_ip)
                                    })
                                    .map(bounce_gdp)
                                    .map(|packet| Ok(packet.deparse()))
                                    .map(encrypt_gdp)
                                    .emit(q)
                                    .replace(|_| unreachable!())
                            }
                        })
                },
                GdpAction::RibReply => |group| {
                    group
                        .for_each(move |packet| handle_rib_reply(packet, store, debug))
                        .filter(move |_| false)
                }
            },
        )
        // drop dTLS header before forwarding to library
        .map(|packet| packet.deparse().remove())
        .map(|mut packet| {
            packet.reconcile_all();
            Ok(packet)
        })
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
    let loc_mac_addr = q.mac_addr();

    Poll::new(q.clone())
        .map(|packet| packet.parse::<Ethernet>())
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
                            let udp = packet.envelope_mut().envelope_mut();
                            udp.set_dst_port(RIB_PORT);
                            let ipv4 = udp.envelope_mut();
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
                        .map(move |mut packet| {
                            let udp = packet.envelope_mut().envelope_mut();
                            bounce_udp(udp);
                            udp.set_src_ip(INTERNAL_IP)?;
                            let ethernet = udp.envelope_mut().envelope_mut();
                            ethernet.set_src(loc_mac_addr);
                            let mut udp = packet.deparse().remove()?;
                            udp.reconcile_all();
                            Ok(udp)
                        })
                        .emit(q) // send out of TAP, not bound NIC
                        .replace(|_| unreachable!())
                },
            },
        )
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
}

pub fn start_sidecar_listener(
    config: RuntimeConfig,
    gdp_index: u8,
    node_addr: Ipv4Addr,
    switch_addr: Ipv4Addr,
    nic_name: &'static str,
    debug: bool,
    env: Env,
) -> Result<()> {
    let gdp_name = gdp_name_of_index(gdp_index);
    let meta = metadata_of_index(gdp_index);
    let private_key = private_key_of_index(gdp_index);

    let state: &SidecarState = Box::leak(Box::new(SidecarState {
        listen_addr: RwLock::new((MacAddr::broadcast(), Ipv4Addr::UNSPECIFIED, 31415)),
    }));

    let store = SharedStore::new();

    let barrier1 = Arc::new(Barrier::new(2));
    let barrier2 = barrier1.clone();

    build_runtime(config, env)?
        .add_pipeline_to_core(0, move |q| {
            Schedule::new("incoming", async move {
                send_rib_query(
                    q["eth1"].clone(),
                    node_addr,
                    gdp_name,
                    switch_addr,
                    &RibQuery::announce_routes(
                        meta,
                        vec![
                            RtCert::new_wrapped(
                                meta,
                                private_key,
                                CertDest::GdpName(gdp_name_of_index(2)),
                                true,
                            )
                            .unwrap(),
                            RtCert::new_wrapped(
                                meta,
                                private_key,
                                CertDest::IpAddr(node_addr),
                                true,
                            )
                            .unwrap(),
                        ]
                        .into(),
                    ),
                    nic_name,
                );
                barrier1.wait().await;
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
                .await
            })
        })?
        .add_pipeline_to_core(1, move |q| {
            Schedule::new("outgoing", async move {
                barrier2.wait().await;
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
                .await;
            })
        })?
        .execute()?;
    Ok(())
}
