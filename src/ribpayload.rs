use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::kvs::GdpName;

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct RibQuery {
    pub gdp_name: GdpName,
}

impl RibQuery {
    pub fn new(gdp_name: GdpName) -> Self {
        RibQuery { gdp_name }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct RibResponse {
    pub gdp_name: GdpName,
    pub ip: Ipv4Addr,
    pub ttl: u64,
}

impl RibResponse {
    pub fn new(gdp_name: GdpName, ip: Ipv4Addr, ttl: u64) -> Self {
        RibResponse { gdp_name, ip, ttl }
    }
}
