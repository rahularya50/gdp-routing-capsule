#![feature(array_methods)]
#![feature(destructuring_assignment)]

use std::fs;

use anyhow::Result;
use capsule::packets::ip::v4::Ipv4;
use clap::{arg_enum, clap_app, value_t};
use tracing::Level;
use tracing_subscriber::fmt;

use crate::certificates::{test_signatures, GdpRoute};
use crate::devsetup::start_dev_server;
use crate::dtls::DTls;
use crate::kvs::FwdTableEntry;
use crate::pipeline::GdpPipeline;
use crate::prodsetup::{start_prod_server, ProdMode};
use crate::rib::Route;
use crate::statistics::dump_history;
use crate::workloads::start_client_server;

mod certificates;
mod devsetup;
mod dtls;
mod gdp;
mod gdp_pipeline;
mod gdpbatch;
mod hardcoded_routes;
mod inject;
mod kvs;
mod pipeline;
mod prodsetup;
mod rib;
mod ribpayload;
mod schedule;
mod statistics;
mod switch;
mod workloads;

arg_enum! {
    enum Mode {
        Dev,
        Client,
        Router,
        Switch,
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
        (@arg mode: -m --mode * +takes_value possible_values(&modes[..]) "The type of this node")
        (@arg name: -n --name * +takes_value "The GDPName of this node (used for packet filtering)")
        (@arg use_default: -d --default_routes !takes_value "For Router mode, send default response even when GDP Name is invalid")
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

    let gdp_name = value_t!(matches, "name", u8)?;

    match mode {
        Mode::Dev => start_dev_server(config),
        Mode::Router => start_prod_server(
            config,
            ProdMode::Router,
            gdp_name,
            matches.is_present("use_default"),
        ),
        Mode::Switch => start_prod_server(
            config,
            ProdMode::Switch,
            gdp_name,
            matches.is_present("use_default"),
        ),
        Mode::Client => start_client_server(config, gdp_name),
    }
}
