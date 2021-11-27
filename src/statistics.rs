use crate::Gdp;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Packet;
use chrono;
use hdrhistogram::Histogram;
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
use std::io::LineWriter;

pub struct GdpStatistics {
    pub start_time: u64,
    pub blocks: Vec<GdpStatisticBlock>, // block-level statistics
    pub globals: GdpStatisticGlobal,    // global statistics
    pub block_width: u64,               // time in ms
    pub last_printed_idx: usize,        // idx
}

pub struct GdpStatisticGlobal {
    packet_size_hist: Histogram<u64>,
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
            },
            start_time: chrono::offset::Utc::now()
                .timestamp_millis()
                .try_into()
                .unwrap(),
            block_width: 1000, // default 1s,
            last_printed_idx: 0,
        }
    }

    fn resize_if_needed(&mut self) {
        // resize if necessary, but this should be rare most of the time
        let current_time: u64 = chrono::offset::Utc::now()
            .timestamp_millis()
            .try_into()
            .unwrap();
        if current_time - self.start_time > (self.blocks.len() as u64) * self.block_width {
            self.blocks.resize_with(
                (((current_time - self.start_time) / self.block_width) + 2)
                    .try_into()
                    .unwrap(),
                || GdpStatisticBlock {
                    packet_count: 0,
                    bytes_count: 0,
                },
            );
        }
    }

    pub fn record_packet(&mut self, packet: &Gdp<Ipv4>) {
        let size = packet.payload_len().try_into().unwrap();

        let current_time: u64 = chrono::offset::Utc::now()
            .timestamp_millis()
            .try_into()
            .unwrap();

        self.resize_if_needed();

        // update globals
        let _ = self.globals.packet_size_hist.record(size);

        // update block-levels
        let b_idx: usize = ((current_time - self.start_time) / self.block_width)
            .try_into()
            .unwrap();
        self.blocks[b_idx].packet_count += 1;
        self.blocks[b_idx].bytes_count += size;
    }

    pub fn dump_statistics(&mut self, label: &str) -> std::io::Result<()> {
        // Dump statistics to {label}.log

        self.resize_if_needed();

        // Open a new file and dump the statistics
        let file = File::create(format!("{}.log", label))?;
        let mut file = LineWriter::new(file);

        if self.blocks.len() == 0 {
            return Ok(());
        }

        // Write globals data
        // p99 bandwidth
        // average bandwidth
        file.write_all("globals\n\n".as_bytes())?;
        file.write_all(format!("label: {}\n", label).as_bytes())?;
        file.write_all(format!("block_width: {}ms\n", self.block_width).as_bytes())?;

        // Write
        file.write_all("\n".as_bytes())?;
        file.write_all("block_level\n\n".as_bytes())?;
        file.write_all("time_offset (epoch)\tbytes (B)\tbandwidth (B/s)\n".as_bytes())?;

        // Write block-level bandwidth statistics
        // Cannot write last element since it might not be complete
        for i in 0..(self.blocks.len() - 1) {
            // compute the instantaneous bandwidth
            let blk = &self.blocks[i];
            let bandwidth = (blk.bytes_count as f64 / ((self.block_width as f64) / 1000.0)) as u64;
            let time_offset = self.start_time + self.block_width * (i as u64);
            file.write_all(
                format!("{}\t{}\t{}\n", time_offset, blk.bytes_count, bandwidth).as_bytes(),
            )?;
        }

        file.flush()?;
        self.last_printed_idx = self.blocks.len() - 1;

        Ok(())
    }
}
