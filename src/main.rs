#![feature(array_methods)]

use crate::dtls::{decrypt_gdp, encrypt_gdp, DTls};
use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::kvs::{GdpName, Store};
use crate::pipeline::GdpPipeline;
use crate::rib::load_routes;
use crate::rib::rib_pipeline;
use crate::rib::test_signatures;
use crate::rib::Routes;
use crate::statistics::{dump_history, make_print_stats};
use crate::switch::switch_pipeline;
use crate::workloads::dev_schedule;
use crate::workloads::start_client_server;
use anyhow::Result;
use capsule::batch::{Batch, Either, Pipeline, Poll};
use capsule::config::RuntimeConfig;
use std::time::{SystemTime, UNIX_EPOCH};

use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::{PortQueue, Runtime};
use clap::{arg_enum, clap_app, value_t};

use kvs::FwdTableEntry;
use rib::Route;
use std::fs;
use std::net::Ipv4Addr;
use std::time::Duration;
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
        .filter_map(|mut packet| {
            // Drop if TTL <= 1, otherwise decrement and keep forwarding
            if packet.ttl() <= 1 {
                Ok(Either::Drop(packet.reset()))
            } else {
                packet.set_ttl(packet.ttl() - 1);
                Ok(Either::Keep(packet))
            }
        })
        .for_each(move |packet| {
            // Back-cache the route for 100s to allow NACK to reflect
                store.forwarding_table.put(
                    packet.src(),
                    FwdTableEntry::new(
                        packet.envelope().envelope().envelope().src(),
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            + 100,
                    ),
                );
            Ok(())
        })
        .group_by(
            |packet| packet.action().unwrap_or(GdpAction::Noop),
            gdp_pipeline,
        )
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
    let name1 = "rib1";
    let name2 = "sw1";
    let name3 = "sw2";

    let store1 = Store::new_shared();
    let store2 = Store::new_shared();
    let store3 = Store::new_shared();


    let routes: &'static Routes = Box::leak(Box::new(load_routes()?));

    let (print_stats, history_map) = make_print_stats();

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", move |q| {
            install_gdp_pipeline(
                q.clone(),
                rib_pipeline(false, routes),
                store1.sync(),
                name1,
                Some(Route {
                    ip: Ipv4Addr::new(10, 100, 1, 10),
                    mac: MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0x00),
                }),
            )
        })?
        .add_pipeline_to_port("eth2", move |q| dev_schedule(q, name2, store2.sync()))?
        .add_pipeline_to_port("eth3", move |q| {
            install_gdp_pipeline(
                q,
                switch_pipeline(
                    store3.sync(),
                    routes,
                    Route {
                        ip: Ipv4Addr::new(10, 100, 1, 10),
                        mac: MacAddr::new(0x02, 0x00, 0x00, 0xFF, 0xFF, 0x00),
                    },
                ),
                store3.sync(),
                name3,
                Some(Route {
                    ip: Ipv4Addr::new(10, 100, 1, 12),
                    mac: MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0x02),
                }),
            )
        })?
        .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
        .add_periodic_task_to_core(
            0,
            move || {
                [store1, store2, store3].iter().for_each(|store| {
                    store.sync().run_active_expire()
                })
            },
            Duration::from_secs(1),
        )?
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
    debug: bool,
) -> Result<()> {
    fn create_rib(_store: Store, routes: &'static Routes, debug: bool) -> impl GdpPipeline {
        rib_pipeline(debug, routes)
    }

    fn create_switch(store: Store, routes: &'static Routes, _debug: bool) -> impl GdpPipeline {
        switch_pipeline(store, routes, routes.rib)
    }

    fn start<T: GdpPipeline + 'static>(
        config: RuntimeConfig,
        gdp_name: Option<GdpName>,
        debug: bool,
        pipeline: fn(Store, &'static Routes, bool) -> T,
    ) -> Result<()> {
        let node_addr = gdp_name.map(startup_route_lookup).flatten();

        let store = Store::new_shared();
        let (print_stats, history_map) = make_print_stats();
        let routes: &'static Routes = Box::leak(Box::new(load_routes()?));

        Runtime::build(config)?
            .add_pipeline_to_port("eth1", move |q| {
                let store = store.sync();
                install_gdp_pipeline(q, pipeline(store, routes, debug), store, "prod", node_addr)
            })?
            .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
            .add_periodic_task_to_core(
                0,
                move || store.sync().run_active_expire(),
                Duration::from_secs(1),
            )?
            .execute()?;
        dump_history(&(*history_map.lock().unwrap()))?;
        Ok(())
    }

    match mode {
        ProdMode::Router => start(config, gdp_name, debug, create_rib),
        ProdMode::Switch => start(config, gdp_name, debug, create_switch),
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
        (@arg debug: -d --debug !takes_value "Debug Mode: For Router mode, send default response even when GDP Name is invalid")
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
        Mode::Router => start_prod_server(
            config,
            ProdMode::Router,
            gdp_name.ok(),
            matches.is_present("debug"),
        ),
        Mode::Switch => start_prod_server(
            config,
            ProdMode::Switch,
            Some(gdp_name?),
            matches.is_present("debug"),
        ),
        Mode::Client => start_client_server(config, gdp_name?),
    }
}
