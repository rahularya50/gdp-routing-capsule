use crate::kvs::GdpName;
use crate::DTls;
use hdrhistogram::Histogram;

use anyhow::{anyhow, Result};
use capsule::packets::ip::IpPacket;
use capsule::packets::types::u16be;
use capsule::packets::{Internal, Packet};
use capsule::{ensure, SizeOf};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ptr::NonNull;
use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C)]
struct GdpStatistics {
    start_time: Instant,
    blocks: Vec<GdpStatisticBlock>, // block-level statistics
    globals: GdpStatisticGlobal,    // global statistics
    block_width: u32,               // time in us
}

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C)]
struct GdpStatisticGlobal {
    packet_size_hist: Histogram,
    latency_hist: Histogram,
}

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C)]
struct GdpStatisticBlock {
    start_time: Instant,
    packet_count: u32,
    bytes_count: u64,
}
