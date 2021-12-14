use std::time::Duration;

use anyhow::Result;
use capsule::config::RuntimeConfig;
use capsule::Runtime;

use crate::gdp_pipeline::install_gdp_pipeline;
use crate::hardcoded_routes::{gdp_name_of_index, load_routes, startup_route_lookup};
use crate::kvs::{GdpName, Store};
use crate::pipeline::GdpPipeline;
use crate::rib::{rib_pipeline, Routes};
use crate::statistics::{dump_history, make_print_stats};
use crate::switch::switch_pipeline;

pub enum ProdMode {
    Router,
    Switch,
}

pub fn start_prod_server(
    config: RuntimeConfig,
    mode: ProdMode,
    gdp_index: u8,
    use_default: bool,
) -> Result<()> {
    fn create_rib(
        _gdp_name: GdpName,
        _store: Store,
        routes: &'static Routes,
        use_default: bool,
    ) -> impl GdpPipeline {
        rib_pipeline("rib", routes, use_default, false)
    }

    fn create_switch(
        gdp_name: GdpName,
        store: Store,
        routes: &'static Routes,
        _: bool,
    ) -> impl GdpPipeline {
        switch_pipeline(gdp_name, store, "switch", routes, routes.rib, false)
    }

    fn start<T: GdpPipeline + 'static>(
        config: RuntimeConfig,
        gdp_index: u8,
        use_default: bool,
        pipeline: fn(GdpName, Store, &'static Routes, bool) -> T,
    ) -> Result<()> {
        let gdp_name = gdp_name_of_index(gdp_index);
        let node_addr = startup_route_lookup(gdp_index);

        let store = Store::new_shared();
        let (print_stats, history_map) = make_print_stats();
        let routes: &'static Routes = Box::leak(Box::new(load_routes()?));

        Runtime::build(config)?
            .add_pipeline_to_port("eth1", move |q| {
                let store = store.sync();
                install_gdp_pipeline(
                    q,
                    pipeline(gdp_name, store, routes, use_default),
                    store,
                    "prod",
                    node_addr,
                    false,
                )
            })?
            .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
            .add_periodic_task_to_core(
                0,
                move || store.run_active_expire(),
                Duration::from_secs(1),
            )?
            .execute()?;
        dump_history(&(*history_map.lock().unwrap()))?;
        Ok(())
    }

    match mode {
        ProdMode::Router => start(config, gdp_index, use_default, create_rib),
        ProdMode::Switch => start(config, gdp_index, use_default, create_switch),
    }
}
