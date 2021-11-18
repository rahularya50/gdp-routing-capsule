use chrono;
use hdrhistogram::Histogram;

pub struct GdpStatistics {
    pub start_time: i64,
    pub blocks: Vec<GdpStatisticBlock>, // block-level statistics
    pub globals: GdpStatisticGlobal,    // global statistics
    pub block_width: u32,               // time in us
}

pub struct GdpStatisticGlobal {
    packet_size_hist: Histogram<u64>,
    latency_hist: Histogram<u64>,
}

pub struct GdpStatisticBlock {
    packet_count: u64,
    bytes_count: u64,
}

// something like this
impl GdpStatistics {
    pub fn new() -> Self {
        GdpStatistics {
            blocks: Vec::<GdpStatisticBlock>::new(),
            globals: GdpStatisticGlobal {
                packet_size_hist: Histogram::<u64>::new(5).unwrap(),
                latency_hist: Histogram::<u64>::new(5).unwrap(),
            },
            start_time: chrono::offset::Utc::now().timestamp_millis(),
            block_width: 1, // default 1ms
        }
    }

    pub fn record_packet(&mut self, _size: u64, _latency: u64) {
        // resize if necessary, but this should be rare most of the time
        // let current_time = chrono::offset::Utc::now().timestamp_millis();
        // if current_time - start_time > self.blocks.size() * self.block_width {
        //     self.blocks.resize_with(
        //         (current_time - start_time) / self.block_width,
        //         Default::default,
        //     );
        // }
    }
}
