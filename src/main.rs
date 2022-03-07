#![feature(array_methods)]

use std::fs;
use std::net::Ipv4Addr;

use anyhow::Result;
use capsule::packets::ip::v4::Ipv4;
use clap::{arg_enum, clap_app, value_t};
use tracing::Level;
use tracing_subscriber::fmt;

use crate::devsetup::start_dev_server;
use crate::dtls::DTls;
use crate::kvs::FwdTableEntry;
use crate::pipeline::GdpPipeline;
use crate::prodsetup::{start_prod_server, ProdMode};

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
mod runtime;
mod schedule;
mod statistics;
mod switch;
mod workloads;

arg_enum! {
    #[derive(PartialEq)]
    enum Mode {
        Dev,
        Client,
        Router,
        Switch,
    }
}

arg_enum! {
    #[derive(PartialEq, Copy, Clone)]
    pub enum Env {
        Local,
        Aws,
        Nuc,
    }
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let modes = Mode::variants().map(|s| s.to_lowercase());
    let modes = &modes.each_ref().map(|mode| &(mode[..]));

    let envs = Env::variants().map(|s| s.to_lowercase());
    let envs = &envs.each_ref().map(|env| &(env[..]));

    let matches = clap_app!(capsule =>
        (@arg mode: -m --mode * +takes_value possible_values(&modes[..]) "The type of this node")
        (@arg env: -e --env * +takes_value possible_values(&envs[..]) "The environment in which this node is running")
        (@arg name: -n --name +takes_value "The GDPName of this node (used for packet filtering)")
        (@arg ip: --ip +takes_value "The IP address of this node")
        (@arg switch_ip: -s --switch-ip +takes_value "The IP address of the local switch")
        (@arg use_default: -d --default-routes !takes_value "For Router mode, send default response even when GDP Name is invalid")
    )
    .get_matches();

    let mode = value_t!(matches, "mode", Mode).unwrap_or_else(|e| e.exit());
    let env = value_t!(matches, "env", Env).unwrap_or_else(|e| e.exit());

    let path = if mode == Mode::Dev {
        "conf.toml"
    } else {
        match env {
            Env::Local => "conf.toml",
            Env::Aws => "ec2.toml",
            Env::Nuc => "nuc.toml",
        }
    };

    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;

    let gdp_name = value_t!(matches, "name", u8);
    let ip_addr = value_t!(matches, "ip", Ipv4Addr);
    let switch_addr = value_t!(matches, "switch-ip", Ipv4Addr);

    match mode {
        Mode::Dev => start_dev_server(config),
        Mode::Router => start_prod_server(
            config,
            ProdMode::Router,
            env,
            gdp_name?,
            ip_addr?,
            matches.is_present("use_default"),
        ),
        Mode::Switch => start_prod_server(
            config,
            ProdMode::Switch,
            env,
            gdp_name?,
            ip_addr?,
            matches.is_present("use_default"),
        ),
        Mode::Client => start_client_server(config, ip_addr?, switch_addr?, env),
    }
}
