use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use capsule::config::RuntimeConfig;

use crate::certificates::{CertDest, RtCert};
use crate::gdp_pipeline::install_gdp_pipeline;
use crate::hardcoded_routes::{
    gdp_name_of_index, load_routes, metadata_of_index, private_key_of_index,
};
use crate::kvs::SharedStore;
use crate::rib::{rib_pipeline, send_rib_query, Routes};
use crate::ribpayload::RibQuery;
use crate::runtime::build_runtime;
use crate::statistics::{dump_history, make_print_stats};
use crate::switch::switch_pipeline;
use crate::Env;

pub fn start_rib_server(
    config: RuntimeConfig,
    env: Env,
    node_addr: Ipv4Addr,
    use_default: bool,
    debug: bool,
) -> Result<()> {
    let routes: &'static Routes = Box::leak(Box::new(load_routes(env)?));

    build_runtime(config, env)?
        .add_pipeline_to_port("eth1", move |q| {
            install_gdp_pipeline(
                q,
                rib_pipeline("rib", routes, use_default, debug),
                "prod",
                node_addr,
                debug,
            )
        })?
        .execute()?;
    Ok(())
}

pub fn start_switch_server(
    config: RuntimeConfig,
    env: Env,
    gdp_index: u8,
    node_addr: Ipv4Addr,
    debug: bool,
) -> Result<()> {
    let gdp_name = gdp_name_of_index(gdp_index);
    let meta = metadata_of_index(gdp_index);
    let private_key = private_key_of_index(gdp_index);

    let store = SharedStore::new();
    let (_print_stats, history_map) = make_print_stats();
    let routes: &'static Routes = Box::leak(Box::new(load_routes(env)?));

    let cert = RtCert::new_wrapped(meta, private_key, CertDest::IpAddr(node_addr), true)?;

    build_runtime(config, env)?
        .add_pipeline_to_port("eth1", move |q| {
            let store = store.sync();
            send_rib_query(
                q.clone(),
                node_addr,
                routes.rib.ip,
                &RibQuery::announce_route(meta, cert.clone()),
                "prod",
            );
            install_gdp_pipeline(
                q,
                switch_pipeline(
                    gdp_name,
                    meta,
                    private_key,
                    store,
                    "switch",
                    routes.rib.ip,
                    debug,
                ),
                "prod",
                node_addr,
                debug,
            )
        })?
        // .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
        .add_periodic_task_to_core(0, move || store.run_active_expire(), Duration::from_secs(1))?
        .execute()?;
    dump_history(&(*history_map.lock().unwrap()))?;
    Ok(())
}
