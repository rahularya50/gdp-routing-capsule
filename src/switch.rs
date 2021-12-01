use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::gdpbatch::GdpBatch;
use crate::kvs::Store;

use crate::pipeline;
use crate::pipeline::GdpPipeline;
use crate::rib::create_rib_request;
use crate::rib::handle_rib_reply;
use crate::rib::Routes;
use crate::Route;
use anyhow::anyhow;
use anyhow::Result;
use capsule::batch::Batch;
use capsule::batch::Either;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Packet;
use capsule::packets::Udp;
use capsule::Mbuf;
use std::net::Ipv4Addr;

fn find_destination(gdp: &Gdp<Ipv4>, store: Store) -> Option<Ipv4Addr> {
    store.forwarding_table.get(&gdp.dst())
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
    store: Store,
    routes: &'static Routes,
    rib_route: Route,
) -> impl GdpPipeline {
    pipeline! {
        GdpAction::Forward => |group| {
            group.group_by(
                move |packet| find_destination(packet, store).is_some(),
                pipeline! {
                    true => |group| {
                        group.filter_map(move |packet| {
                            let ip = find_destination(&packet, store).ok_or(anyhow!("can't find the destination"))?;
                            let mac = routes.routes.get(&packet.dst()).unwrap().mac; // FIXME - this is a hack!!!
                            forward_gdp(packet, Route {ip, mac})
                        })
                    }
                    false => |group| {
                        group
                        .map(bounce_gdp)
                        .inject(move |packet| {
                            let src_ip = packet.envelope().envelope().envelope().src();
                            let src_mac = packet.envelope().envelope().envelope().envelope().src();
                            println!("Querying RIB for destination {:?}", packet.dst());
                            create_rib_request(Mbuf::new()?, packet.dst(), src_mac, src_ip, rib_route)
                        })
                    }
                })
        }
        GdpAction::RibReply => |group| {
            group.for_each(move |packet| handle_rib_reply(packet, store))
                .filter(|_| false)
        }
        _ => |group| {group.filter(|_| false)}
    }
}
