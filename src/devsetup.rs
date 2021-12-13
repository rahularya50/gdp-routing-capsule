use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use capsule::config::RuntimeConfig;
use capsule::net::MacAddr;
use capsule::Runtime;

use crate::gdp_pipeline::install_gdp_pipeline;
use crate::hardcoded_routes::load_routes;
use crate::kvs::Store;
use crate::rib::{rib_pipeline, Route, Routes};
use crate::statistics::{dump_history, make_print_stats};
use crate::switch::switch_pipeline;
use crate::workloads::dev_schedule;

pub fn start_dev_server(config: RuntimeConfig) -> Result<()> {
    let store1 = Store::new_shared();
    let store2 = Store::new_shared();
    let store3 = Store::new_shared();

    let routes: &'static Routes = Box::leak(Box::new(load_routes()?));

    let (_print_stats, history_map) = make_print_stats();

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", move |q| {
            let name = "rib";
            install_gdp_pipeline(
                q,
                rib_pipeline(name, routes, false, true),
                store1.sync(),
                name,
                Some(Route {
                    ip: Ipv4Addr::new(10, 100, 1, 10),
                    mac: MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0x00),
                }),
                true,
            )
        })?
        .add_pipeline_to_port("eth2", move |q| dev_schedule(q, "client"))?
        .add_pipeline_to_port("eth3", move |q| {
            let name = "switch";
            let store3_local = store3.sync();
            install_gdp_pipeline(
                q,
                switch_pipeline(
                    store3_local,
                    name,
                    routes,
                    Route {
                        ip: Ipv4Addr::new(10, 100, 1, 10),
                        mac: MacAddr::new(0x02, 0x00, 0x00, 0xFF, 0xFF, 0x00),
                    },
                    true,
                ),
                store3_local,
                name,
                Some(Route {
                    ip: Ipv4Addr::new(10, 100, 1, 12),
                    mac: MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0x02),
                }),
                true,
            )
        })?
        // .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
        .add_periodic_task_to_core(
            0,
            move || {
                [store1, store2, store3]
                    .iter()
                    .for_each(|store| store.sync().run_active_expire())
            },
            Duration::from_secs(1),
        )?
        .execute()?;

    let x = dump_history(&(*history_map.lock().unwrap()));
    x
}
