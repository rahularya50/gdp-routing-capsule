use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use capsule::batch::{Batch, Either};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Packet, Udp};
use capsule::Mbuf;

use crate::certificates::check_packet_certificates;
use crate::gdp::{Gdp, GdpAction};
use crate::gdpbatch::GdpBatch;
use crate::kvs::{GdpName, Store};
use crate::pipeline::GdpPipeline;
use crate::rib::{create_rib_request, handle_rib_reply, Routes};
use crate::ribpayload::RibQuery;
use crate::{pipeline, FwdTableEntry, Route};

fn find_destination(gdp: &Gdp<Ipv4>, store: Store) -> Option<Ipv4Addr> {
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

fn forward_gdp(mut gdp: Gdp<Ipv4>, dst: Route) -> Result<Either<Gdp<Ipv4>>> {
    let dtls = gdp.envelope_mut();
    let udp = dtls.envelope_mut();
    let ipv4 = udp.envelope_mut();

    if ipv4.dst() == dst.ip {
        // we are the destination!
        println!("packet received!");
        return Ok(Either::Drop(gdp.reset()));
    }

    ipv4.set_src(ipv4.dst());
    ipv4.set_dst(dst.ip);

    let ethernet = ipv4.envelope_mut();
    ethernet.set_src(ethernet.dst());
    ethernet.set_dst(dst.mac);

    Ok(Either::Keep(gdp))
}

fn bounce_gdp(mut gdp: Gdp<Ipv4>) -> Result<Gdp<Ipv4>> {
    gdp.remove_payload()?;
    gdp.set_action(GdpAction::Nack);
    bounce_udp(gdp.envelope_mut().envelope_mut());
    gdp.reconcile_all();
    Ok(gdp)
}

pub fn switch_pipeline(
    gdp_name: GdpName,
    store: Store,
    nic_name: &'static str,
    routes: &'static Routes,
    rib_route: Route,
    debug: bool,
) -> impl GdpPipeline {
    pipeline! {
        GdpAction::Forward => |group| {
            group
            .filter(move |packet| {
                check_packet_certificates(gdp_name, packet, &store, None, nic_name, debug)
            })
            .for_each(move |packet| {
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
                            let mac = routes.routes.get(&packet.dst()).unwrap_or(&routes.default).mac; // FIXME - this is a hack!!!
                            if debug {
                                println!("{} forwarding packet to ip {} mac {}", nic_name, ip, mac);
                            }
                            forward_gdp(packet, Route {ip, mac})
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
                            create_rib_request(Mbuf::new()?, &RibQuery::next_hop_for(packet.dst()), src_mac, src_ip, rib_route)
                        })
                    }
                })
        }
        GdpAction::RibReply => |group| {
            group.for_each(move |packet| handle_rib_reply(packet, store))
                .filter(|_| false)
        }
        GdpAction::Nack => |group| {
            group.filter_map(move |packet| {
                let route = store.nack_reply_cache.get(&packet.src());
                let mac = routes.routes.get(&packet.dst()).unwrap_or(&routes.default).mac; // FIXME - this is a hack!!!
                match route {
                    Some(FwdTableEntry { ip, .. }) => forward_gdp(packet, Route { ip, mac }),
                    None => Ok(Either::Drop(packet.reset())),
                }
            })
        }
        GdpAction::RibGet => |group| {
            group.filter_map(move |packet| forward_gdp(packet, rib_route))
        }
        _ => |group| {group.filter(|_| false)}
    }
}
