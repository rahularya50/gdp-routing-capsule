#![feature(array_methods)]

use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::kvs::{GdpName, Store};
use crate::pipeline::GdpPipeline;
use crate::rib::load_routes;
use crate::rib::rib_pipeline;
use crate::rib::test_signatures;
use crate::statistics::{dump_history, make_print_stats};
use crate::switch::switch_pipeline;
use crate::workloads::dev_schedule;
use crate::workloads::start_client_server;
use anyhow::Result;
use capsule::batch::{Batch, Pipeline, Poll};
use capsule::config::RuntimeConfig;

use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::{PortQueue, Runtime};
use clap::{arg_enum, clap_app, value_t};

use rib::Route;

use std::fs;

use std::time::Duration;

use std::net::Ipv4Addr;

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
mod switch;
mod workloads;

pub trait GdpPipelineBuilder: Fn(&Store) -> Box<dyn GdpPipeline> {}
impl<T: Fn(&Store) -> Box<dyn GdpPipeline>> GdpPipelineBuilder for T {}

fn install_gdp_pipeline<'a>(
    q: PortQueue,
    gdp_pipeline: impl GdpPipeline,
    store: Store,
    _nic_name: &'a str,
    node_addr: Option<Route>,
) -> impl Pipeline + 'a {
    Poll::new(q.clone())
        .map(|packet| Ok(packet.parse::<Ethernet>()?.parse::<Ipv4>()?))
        .filter(move |packet| {
            if let Some(node_addr) = node_addr {
                packet.dst() == node_addr.ip && packet.envelope().dst() == node_addr.mac
            } else {
                true
            }
        })
        .map(|packet| Ok(packet.parse::<Udp<Ipv4>>()?.parse::<DTls<Ipv4>>()?))
        .map(decrypt_gdp)
        .map(|packet| Ok(packet.parse::<Gdp<Ipv4>>()?))
        .for_each(move |packet| {
            // Back-cache the route to allow NACK to reflect
            store
                .forwarding_table
                .put(packet.src(), packet.envelope().envelope().envelope().src());
            //println!("Parsed gdp packet in NIC {:?}: {:?}", nic_name, packet);

            // Record incoming packet statistics
            // store.with_mut_contents(|store| {
            //     store.in_statistics.record_packet(packet);
            // });
            Ok(())
        })
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            gdp_pipeline,
        )
        .for_each(move |_packet| {
            //println!("Sent gdp packet in NIC {:?}: {:?}", nic_name, packet);

            // Record outgoing packet statistics
            // store.with_mut_contents(|store| {
            //     store.out_statistics.record_packet(packet);
            // });
            Ok(())
        })
        .map(|packet| Ok(packet.deparse()))
        .map(encrypt_gdp)
        .send(q)
}

arg_enum! {
    enum Mode {
        Dev,
        Client,
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
    let name2 = "sw1";
    let name3 = "sw2";

    let pipeline1 = rib_pipeline()?;
    let pipeline3 = switch_pipeline(
        store3,
        Route {
            ip: Ipv4Addr::new(10, 100, 1, 10),
            mac: MacAddr::new(0x02, 0x00, 0x00, 0xFF, 0xFF, 0x00),
        },
    )?;

    let (print_stats, history_map) = make_print_stats();

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", move |q| {
            install_gdp_pipeline(
                q.clone(),
                pipeline1(),
                store1,
                name1,
                Some(Route {
                    ip: Ipv4Addr::new(10, 100, 1, 10),
                    mac: MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0x00),
                }),
            )
        })?
        .add_pipeline_to_port("eth2", move |q| dev_schedule(q, name2, store2))?
        .add_pipeline_to_port("eth3", move |q| {
            install_gdp_pipeline(
                q,
                pipeline3(),
                store3,
                name3,
                Some(Route {
                    ip: Ipv4Addr::new(10, 100, 1, 12),
                    mac: MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0x02),
                }),
            )
        })?
        .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
        .execute()?;

    let x = dump_history(&(*history_map.lock().unwrap()));
    x
}

pub fn startup_route_lookup(gdp_name: GdpName) -> Option<Route> {
    // FIXME: this is an awful hack, we shouldn't need to read the RIB to get our IP addr!
    load_routes()
        .ok()?
        .routes
        .get(&gdp_name)
        .map(|route| route.to_owned())
}

fn start_prod_server(
    config: RuntimeConfig,
    mode: ProdMode,
    gdp_name: Option<GdpName>,
) -> Result<()> {
    let store = Store::new();

    let node_addr = gdp_name.map(startup_route_lookup).flatten();

    fn start(
        config: RuntimeConfig,
        store: Store,
        pipeline: impl GdpPipelineBuilder,
        node_addr: Option<Route>,
    ) -> Result<()> {
        let (print_stats, history_map) = make_print_stats();

        Runtime::build(config)?
            .add_pipeline_to_port("eth1", move |q| {
                install_gdp_pipeline(q, pipeline(), store, "prod", node_addr)
            })?
            .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
            .execute()?;

        let x = dump_history(&(*history_map.lock().unwrap()));
        x
    }

    match mode {
        ProdMode::Router => start(config, store, rib_pipeline()?, node_addr),
        ProdMode::Switch => start(
            config,
            store,
            switch_pipeline(store, load_routes()?.rib)?,
            node_addr,
        ),
    }
}

fn main() -> Result<()> {
    test_signatures(b"go bears").unwrap();

    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let modes = Mode::variants().map(|s| s.to_lowercase());
    let modes = &modes.each_ref().map(|mode| &(mode[..]));

    let matches = clap_app!(capsule =>
        (@arg mode: -m --mode * +takes_value possible_values(&modes[..])
        requires_if("switch", "name")
        "The type of this node")
        (@arg name: -n --name +takes_value "The GDPName of this node (used for packet filtering)")
    )
    .get_matches();

    let mode = value_t!(matches, "mode", Mode).unwrap_or_else(|e| e.exit());
    let path = match mode {
        Mode::Dev => "conf.toml",
        Mode::Router => "ec2.toml",
        Mode::Switch => "ec2.toml",
        Mode::Client => "ec2.toml",
    };

    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;

    let gdp_name = value_t!(matches, "name", GdpName);

    match mode {
        Mode::Dev => start_dev_server(config),
        Mode::Router => start_prod_server(config, ProdMode::Router, gdp_name.ok()),
        Mode::Switch => start_prod_server(config, ProdMode::Switch, Some(gdp_name?)),
        Mode::Client => start_client_server(config, gdp_name?),
    }
}
