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
use crate::workloads::dev_schedule;
use crate::Env;

pub fn start_dev_server(config: RuntimeConfig) -> Result<()> {
    let store1 = SharedStore::new();
    let store2 = SharedStore::new();
    let store3 = SharedStore::new();
    let store4 = SharedStore::new();

    let routes: &'static Routes = Box::leak(Box::new(load_routes(Env::Local)?));

    let (_print_stats, history_map) = make_print_stats();

    let rib_ip = Ipv4Addr::new(10, 100, 1, 10);

    const DEBUG: bool = true;

    build_runtime(config, Env::Local)?
        // GDP index = 4
        .add_pipeline_to_port("eth1", move |q| {
            let name = "rib";
            let node_addr = Ipv4Addr::new(10, 100, 1, 10);
            install_gdp_pipeline(
                q,
                rib_pipeline(name, routes, false, DEBUG),
                name,
                node_addr,
                DEBUG,
            )
        })?
        // GDP index = 1
        .add_pipeline_to_port("eth2", move |q| dev_schedule(q, "client"))?
        // GDP index = 2
        .add_pipeline_to_port("eth3", move |q| {
            let name = "switch";
            let store3_local = store3.sync();
            let meta = metadata_of_index(2);
            let private_key = private_key_of_index(2);
            let node_addr = Ipv4Addr::new(10, 100, 1, 12);
            send_rib_query(
                q.clone(),
                node_addr,
                gdp_name_of_index(2),
                rib_ip,
                &RibQuery::announce_route(
                    meta,
                    RtCert::new_wrapped(meta, private_key, CertDest::IpAddr(node_addr), true)
                        .unwrap(),
                ),
                name,
            );
            install_gdp_pipeline(
                q,
                switch_pipeline(
                    gdp_name_of_index(2),
                    meta,
                    private_key,
                    store3_local,
                    name,
                    rib_ip,
                    DEBUG,
                ),
                name,
                node_addr,
                DEBUG,
            )
        })?
        // GDP index = 3
        .add_pipeline_to_port("eth4", move |q| {
            let name = "target";
            let store4_local = store4.sync();
            let meta = metadata_of_index(3);
            let private_key = private_key_of_index(3);
            let node_addr = Ipv4Addr::new(10, 100, 1, 13);
            send_rib_query(
                q.clone(),
                node_addr,
                gdp_name_of_index(3),
                rib_ip,
                &RibQuery::announce_route(
                    meta,
                    RtCert::new_wrapped(meta, private_key, CertDest::IpAddr(node_addr), true)
                        .unwrap(),
                ),
                name,
            );
            install_gdp_pipeline(
                q,
                switch_pipeline(
                    gdp_name_of_index(3),
                    meta,
                    private_key,
                    store4_local,
                    name,
                    rib_ip,
                    DEBUG,
                ),
                name,
                node_addr,
                DEBUG,
            )
        })?
        // .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
        .add_periodic_task_to_core(
            0,
            move || {
                [store1, store2, store3]
                    .iter()
                    .for_each(|store| store.run_active_expire())
            },
            Duration::from_secs(1),
        )?
        .execute()?;

    let x = dump_history(&(*history_map.lock().unwrap()));
    x
}
