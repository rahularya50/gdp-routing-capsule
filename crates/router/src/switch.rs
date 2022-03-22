use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use capsule::batch::{Batch, Either};
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Packet, Udp};
use capsule::Mbuf;
use client::{GdpAction, GdpName};

use crate::certificates::{check_packet_certificates, CertDest, GdpMeta, RtCert};
use crate::dtls::DTls;
use crate::gdp::{CertificateBlock, Gdp};
use crate::gdpbatch::GdpBatch;
use crate::hardcoded_routes::WithBroadcast;
use crate::kvs::Store;
use crate::pipeline::GdpPipeline;
use crate::rib::{create_rib_request, handle_rib_reply};
use crate::ribpayload::RibQuery;
use crate::{pipeline, FwdTableEntry};

fn find_destination(gdp: &Gdp<DTls<Ipv4>>, store: Store) -> Option<Ipv4Addr> {
    store.forwarding_table.get(&gdp.dst()).map(|x| x.ip)
}

fn bounce_udp(udp: &mut Udp<Ipv4>) {
    let udp_src_port = udp.dst_port();
    let udp_dst_port = udp.src_port();
    udp.set_src_port(udp_src_port);
    udp.set_dst_port(udp_dst_port);

    let ipv4 = udp.envelope_mut();
    let ip_src = ipv4.dst();
    let ip_dst = ipv4.src();
    ipv4.set_src(ip_src);
    ipv4.set_dst(ip_dst);

    let ethernet = ipv4.envelope_mut();
    let eth_src = ethernet.dst();
    let eth_dst = ethernet.src();
    ethernet.set_src(eth_src);
    ethernet.set_dst(eth_dst);
}

fn add_forwarding_cert(
    mut gdp: Gdp<DTls<Ipv4>>,
    store: Store,
    meta: GdpMeta,
    private_key: [u8; 32],
) -> Result<Gdp<DTls<Ipv4>>> {
    let CertificateBlock { mut certificates } = gdp.get_certs()?;

    let cert = match store.route_certs.get(&gdp.dst()) {
        Some(cert) => cert,
        None => {
            let cert = RtCert::new_wrapped(meta, private_key, CertDest::GdpName(gdp.dst()), false)?;
            store.route_certs.put(gdp.dst(), cert.clone());
            cert
        }
    };

    certificates.push(cert);
    gdp.set_certs(&CertificateBlock { certificates })?;
    Ok(gdp)
}

fn forward_gdp(mut gdp: Gdp<DTls<Ipv4>>, dst: Ipv4Addr) -> Result<Either<Gdp<DTls<Ipv4>>>> {
    let dtls = gdp.envelope_mut();
    let udp = dtls.envelope_mut();
    let ipv4 = udp.envelope_mut();

    if ipv4.dst() == dst {
        // we are the destination!
        println!("packet received!");
        return Ok(Either::Drop(gdp.reset()));
    }

    ipv4.set_src(ipv4.dst());
    ipv4.set_dst(dst);

    let ethernet = ipv4.envelope_mut();
    ethernet.set_src(ethernet.dst());
    ethernet.set_dst(MacAddr::broadcast());
    Ok(Either::Keep(gdp))
}

fn bounce_gdp(mut gdp: Gdp<DTls<Ipv4>>) -> Result<Gdp<DTls<Ipv4>>> {
    if gdp.action()? == GdpAction::Forward {
        gdp.remove_payload()?;
        gdp.set_data_len(0);
        gdp.set_action(GdpAction::Nack);
        bounce_udp(gdp.envelope_mut().envelope_mut());
        gdp.reconcile_all();
    }
    Ok(gdp)
}

pub fn switch_pipeline(
    gdp_name: GdpName,
    meta: GdpMeta,
    private_key: [u8; 32],
    store: Store,
    nic_name: &'static str,
    rib_ip: Ipv4Addr,
    debug: bool,
) -> impl GdpPipeline<DTls<Ipv4>> {
    pipeline! {
        GdpAction::Forward => |group| {
            group
            .group_by(
                move |packet: &Gdp<DTls<Ipv4>>| {
                    check_packet_certificates(gdp_name, packet, &store, None, nic_name, debug)
                },
                pipeline! {
                    true => |group| {
                        group
                        .for_each(move |packet: &Gdp<DTls<Ipv4>>| {
                            // Back-cache the route for 100s to allow NACK to reflect
                            store.nack_reply_cache.put(
                                packet.src(),
                                FwdTableEntry::new(
                                    packet.envelope().envelope().envelope().src(),
                                    SystemTime::now()
                                        .duration_since(UNIX_EPOCH)?
                                        .as_secs()
                                        + 100,
                                ),
                            );
                            Ok(())
                        })
                        .group_by(
                            move |packet| find_destination(packet, store).is_some(),
                            pipeline! {
                                true => |group| {
                                    group.filter_map(move |packet| {
                                        let ip = find_destination(&packet, store).unwrap();
                                        if debug {
                                            println!("{} forwarding packet to ip {}", nic_name, ip);
                                        }
                                        let packet = add_forwarding_cert(packet, store, meta, private_key)?;
                                        forward_gdp(packet, ip)
                                    })
                                }
                                false => |group| {
                                    group
                                    .map(bounce_gdp)
                                    .inject(move |packet| {
                                        let src_ip = packet.envelope().envelope().envelope().src();
                                        let src_mac = packet.envelope().envelope().envelope().envelope().src();
                                        if debug {
                                            println!("{} querying RIB for destination {:?}", nic_name, packet.dst());
                                        }
                                        create_rib_request(Mbuf::new()?, &RibQuery::next_hop_for(packet.dst()), src_mac, src_ip, rib_ip)
                                    })
                                }
                            }
                        )
                    }
                    false => |group| {
                        group
                        .inject(move |packet| {
                            let src_ip = packet.envelope().envelope().envelope().dst();
                            let src_mac = packet.envelope().envelope().envelope().envelope().dst();
                            let mut unknown_names = Vec::new();
                            check_packet_certificates(gdp_name, packet, &store, Some(&mut unknown_names), nic_name, debug,);
                            if debug {
                                println!("{} querying RIB for metas {:?}", nic_name, packet.dst());
                            }
                            create_rib_request(Mbuf::new()?, &RibQuery::metas_for(&unknown_names), src_mac, src_ip, rib_ip)
                        })
                        .map(bounce_gdp)
                    }
                }
            )
        }
        GdpAction::RibReply => |group| {
            group.for_each(move |packet| handle_rib_reply(packet, store, debug))
                .filter(|_| false)
        }
        GdpAction::Nack => |group| {
            group.filter_map(move |packet| {
                let route = store.nack_reply_cache.get(&packet.src());
                match route {
                    Some(FwdTableEntry { ip, .. }) => forward_gdp(packet, ip),
                    None => Ok(Either::Drop(packet.reset())),
                }
            })
        }
        GdpAction::RibGet => |group| {
            group.filter_map(move |packet| forward_gdp(packet, rib_ip))
        }
        _ => |group| {group.filter(|_| false)}
    }
}
