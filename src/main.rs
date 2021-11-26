use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::gdpbatch::GdpBatch;
use crate::kvs::Store;
use crate::pipeline::GdpPipeline;
use crate::rib::create_rib_request;
use crate::rib::handle_rib_query;
use crate::rib::handle_rib_reply;
use crate::rib::load_routes;
use crate::rib::test_signatures;
use crate::rib::Routes;
use crate::workloads::dev_schedule;
use anyhow::anyhow;
use anyhow::Result;
use capsule::batch::{Batch, Pipeline, Poll};
use capsule::config::RuntimeConfig;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::Mbuf;
use capsule::{PortQueue, Runtime};
use clap::{arg_enum, clap_app, value_t};
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::thread;
use tracing::Level;
use tracing_subscriber::fmt;

mod dtls;
mod gdp;
mod gdpbatch;
mod inject;
mod kvs;
mod pipeline;
mod rib;
mod schedule;
mod statistics;
mod workloads;

fn find_destination(gdp: &Gdp<Ipv4>, store: Store) -> Option<Ipv4Addr> {
    store.with_contents(|store| store.forwarding_table.get(&gdp.dst()).cloned())
}

fn bounce_udp(udp: &mut Udp<Ipv4>) -> &mut Udp<Ipv4> {
    let udp_src_port = udp.dst_port();
    let udp_dst_port = udp.src_port();
    udp.set_src_port(udp_src_port);
    udp.set_dst_port(udp_dst_port);

    let ethernet = udp.envelope_mut();
    let eth_src = ethernet.dst();
    let eth_dst = ethernet.src();
    ethernet.set_src(eth_src);
    ethernet.set_dst(eth_dst);

    udp
}

fn forward_gdp(mut gdp: Gdp<Ipv4>, dst: Ipv4Addr) -> Result<Gdp<Ipv4>> {
    let dtls = gdp.envelope_mut();
    let udp = dtls.envelope_mut();
    let ipv4 = udp.envelope_mut();

    ipv4.set_src(ipv4.dst());
    ipv4.set_dst(dst);

    Ok(gdp)
}

fn bounce_gdp(mut gdp: Gdp<Ipv4>) -> Result<Gdp<Ipv4>> {
    gdp.remove_payload()?;
    gdp.set_action(GdpAction::Nack);
    bounce_udp(gdp.envelope_mut().envelope_mut());
    gdp.reconcile_all();
    Ok(gdp)
}

fn switch_pipeline(store: Store) -> impl GdpPipeline + Copy {
    pipeline! {
        GdpAction::Forward => |group| {
            group.group_by(
                move |packet| find_destination(packet, store).is_some(),
                pipeline! {
                    true => |group| {
                        group.map(move |packet| {
                            let dst = find_destination(&packet, store).ok_or(anyhow!("can't find the destination"))?;
                            forward_gdp(packet, dst)
                        })
                    }
                    false => |group| {
                        group
                        .map(bounce_gdp)
                        .inject(move |packet| {
                            let src_ip = packet.envelope().envelope().envelope().src();
                            let src_mac = packet.envelope().envelope().envelope().envelope().dst();
                            println!("Querying RIB for destination {:?}", packet.dst());
                            create_rib_request(Mbuf::new()?, packet.dst(), src_mac, src_ip, store)
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

fn rib_pipeline() -> Result<impl GdpPipeline + Copy> {
    let routes: &Routes = Box::leak(Box::new(load_routes("routes.toml")?));
    Ok(pipeline! {
        GdpAction::RibGet => |group| {
            group.replace(move |packet| handle_rib_query(packet, routes))
        }
        _ => |group| {group.filter(|_| false)}
    })
}

fn install_gdp_pipeline<'a>(
    q: PortQueue,
    gdp_pipeline: impl GdpPipeline,
    store: Store,
    nic_name: &'a str,
) -> impl Pipeline + 'a {
    Poll::new(q.clone())
        .map(|packet| {
            Ok(packet
                .parse::<Ethernet>()?
                .parse::<Ipv4>()?
                .parse::<Udp<Ipv4>>()?
                .parse::<DTls<Ipv4>>()?)
        })
        .map(decrypt_gdp)
        .map(|packet| Ok(packet.parse::<Gdp<Ipv4>>()?))
        .for_each(move |packet| {
            // Back-cache the route to allow NACK to reflect
            store.with_mut_contents(|store| {
                store
                    .forwarding_table
                    .insert(packet.src(), packet.envelope().envelope().envelope().src());
            });
            println!("Parsed gdp packet in NIC {:?}: {:?}", nic_name, packet);

            // Record incoming packet statistics
            store.with_mut_contents(|store| {
                store.in_statistics.record_packet(packet);
            });
            Ok(())
        })
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            gdp_pipeline,
        )
        .for_each(move |packet| {
            println!("Sent gdp packet in NIC {:?}: {:?}", nic_name, packet);

            // Record outgoing packet statistics
            store.with_mut_contents(|store| {
                store.out_statistics.record_packet(packet);
            });
            Ok(())
        })
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .send(q)
}

arg_enum! {
    enum Mode {
        Dev,
        Router,
        Switch,
    }
}

enum ProdMode {
    Router,
    Switch,
}

fn start_dev_server(config: RuntimeConfig) -> Result<()> {
    let store1 = Store::new();
    let store2 = Store::new();
    let store3 = Store::new();

    let name1 = "rib1";
    let _name2 = "sw1";
    let name3 = "sw2";

    // Command handling thread
    thread::spawn(move || -> Result<()> {
        loop {
            let mut buffer = String::new();
            let _ = io::stdin().read_line(&mut buffer);
            buffer.pop(); // erase newline
            println!("Received command {:?}", buffer);
            if buffer == "dump" {
                println!("Dumping statistics to file");
                store2.with_mut_contents(|s| -> Result<()> {
                    let in_label = "store2_in";
                    let out_label = "store2_out";
                    s.in_statistics.dump_statistics(in_label)?;
                    s.out_statistics.dump_statistics(out_label)?;
                    Ok(())
                })?;
                store3.with_mut_contents(|s| -> Result<()> {
                    let in_label = "store3_in";
                    let out_label = "store3_out";
                    s.in_statistics.dump_statistics(in_label)?;
                    s.out_statistics.dump_statistics(out_label)?;
                    Ok(())
                })?;
            }
        }
    });

    let pipeline1 = rib_pipeline()?;
    Runtime::build(config)?
        .add_pipeline_to_port("eth1", move |q| {
            install_gdp_pipeline(q.clone(), pipeline1, store1, name1)
        })?
        .add_pipeline_to_port("eth2", move |q| dev_schedule(q, "dev schedule", store2))?
        .add_pipeline_to_port("eth3", move |q| {
            install_gdp_pipeline(q, switch_pipeline(store3), store3, name3)
        })?
        .execute()
}

fn start_prod_server(config: RuntimeConfig, mode: ProdMode) -> Result<()> {
    let store = Store::new();

    fn start<T: GdpPipeline + Send + Sync + Copy + 'static>(
        config: RuntimeConfig,
        store: Store,
        pipeline: T,
    ) -> Result<()> {
        Runtime::build(config)?
            .add_pipeline_to_port("eth1", move |q| {
                install_gdp_pipeline(q, pipeline, store, "prod")
            })?
            .execute()
    }

    match mode {
        ProdMode::Router => start(config, store, rib_pipeline()?),
        ProdMode::Switch => start(config, store, switch_pipeline(store)),
    }
}

fn main() -> Result<()> {
    test_signatures(b"go bears").unwrap();

    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let matches = clap_app!(capsule =>
        (@arg mode: -m --mode * +takes_value +case_insensitive possible_values(&Mode::variants()) "The mode of the node (dev/router/switch)")
    )
    .get_matches();

    let mode = value_t!(matches, "mode", Mode).unwrap_or_else(|e| e.exit());
    let path = match mode {
        Mode::Dev => "conf.toml",
        Mode::Router => "ec2.toml",
        Mode::Switch => "ec2.toml",
    };

    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;

    match mode {
        Mode::Dev => start_dev_server(config),
        Mode::Router => start_prod_server(config, ProdMode::Router),
        Mode::Switch => start_prod_server(config, ProdMode::Switch),
    }
}
