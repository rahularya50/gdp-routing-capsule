use std::collections::HashMap;
use std::fs;

use anyhow::Result;
use serde::Deserialize;

use crate::certificates::GdpRoute;
use crate::kvs::GdpName;
use crate::rib::{Route, Routes};

#[derive(Deserialize)]
struct SerializedRoutes {
    routes: HashMap<String, Route>,
    rib: Route,
    default: Route,
}

pub fn startup_route_lookup(index: u8) -> Option<Route> {
    // FIXME: this is an awful hack, we shouldn't need to read the RIB to get our IP addr!
    let gdp_name = GdpRoute::gdp_name_of_index(index);
    Some(
        load_routes()
            .ok()?
            .routes
            .get(&gdp_name)
            .map(|route| route.to_owned())?
            .route,
    )
}

pub fn load_routes() -> Result<Routes> {
    let content = fs::read_to_string("routes.toml")?;
    let serialized: SerializedRoutes = toml::from_str(&content)?;

    Ok(Routes {
        routes: serialized
            .routes
            .iter()
            .map(|it| -> (GdpName, GdpRoute) {
                let index = it.0.parse::<u8>().unwrap();
                let route = it.1.to_owned();
                let gdp_route = GdpRoute::from_serial_entry(index, route);
                (gdp_route.name, gdp_route)
            })
            .collect(),
        rib: serialized.rib,
        default: GdpRoute::from_serial_entry(u8::MAX, serialized.default),
    })
}
