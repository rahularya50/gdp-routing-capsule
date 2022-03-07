use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Result};
use capsule::config::RuntimeConfig;

use crate::certificates::{CertDest, GdpMeta, RtCert};
use crate::gdp_pipeline::install_gdp_pipeline;
use crate::hardcoded_routes::{
    gdp_name_of_index, load_routes, metadata_of_index, private_key_of_index,
};
use crate::kvs::{GdpName, Store};
use crate::pipeline::GdpPipeline;
use crate::rib::{rib_pipeline, send_rib_query, Routes};
use crate::ribpayload::RibQuery;
use crate::runtime::build_runtime;
use crate::statistics::{dump_history, make_print_stats};
use crate::switch::switch_pipeline;
use crate::Env;

pub enum ProdMode {
    Router,
    Switch,
}

pub fn start_prod_server(
    config: RuntimeConfig,
    mode: ProdMode,
    env: Env,
    gdp_index: u8,
    node_addr: Ipv4Addr,
    use_default: bool,
) -> Result<()> {
    fn create_rib(
        _gdp_name: GdpName,
        _meta: GdpMeta,
        _private_key: [u8; 32],
        _store: Store,
        routes: &'static Routes,
        use_default: bool,
    ) -> impl GdpPipeline {
        rib_pipeline("rib", routes, use_default, false)
    }

    fn create_switch(
        gdp_name: GdpName,
        meta: GdpMeta,
        private_key: [u8; 32],
        store: Store,
        routes: &'static Routes,
        _: bool,
    ) -> impl GdpPipeline {
        switch_pipeline(
            gdp_name,
            meta,
            private_key,
            store,
            "switch",
            routes.rib.ip,
            false,
        )
    }

    fn start<T: GdpPipeline + 'static>(
        config: RuntimeConfig,
        gdp_index: u8,
        node_addr: Ipv4Addr,
        env: Env,
        use_default: bool,
        pipeline: fn(GdpName, GdpMeta, [u8; 32], Store, &'static Routes, bool) -> T,
    ) -> Result<()> {
        let gdp_name = gdp_name_of_index(gdp_index);
        let meta = metadata_of_index(gdp_index);
        let private_key = private_key_of_index(gdp_index);

        let store = Store::new_shared();
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
                    pipeline(gdp_name, meta, private_key, store, routes, use_default),
                    "prod",
                    node_addr,
                    false,
                )
            })?
            // .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
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
        ProdMode::Router => start(config, gdp_index, node_addr, env, use_default, create_rib),
        ProdMode::Switch => start(
            config,
            gdp_index,
            node_addr,
            env,
            use_default,
            create_switch,
        ),
    }
}
