mod structs;

use std::intrinsics::transmute;
use std::mem::size_of;
use std::net::{SocketAddr, UdpSocket};

use anyhow::{ensure, Result};

pub use crate::structs::{GdpAction, GdpHeader, GdpName, MAGIC_NUMBERS};

pub struct GDPClient {
    socket: UdpSocket,
}

impl GDPClient {
    pub fn new(lib_port: u16, sidecar_port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], lib_port)))?;
        socket.connect(SocketAddr::from(([127, 0, 0, 1], sidecar_port)))?;
        Ok(GDPClient { socket })
    }

    pub fn send_packet(&self, dest: GdpName, payload: &[u8]) -> Result<()> {
        let mut buffer = vec![];
        let header = GdpHeader {
            field: MAGIC_NUMBERS.into(),
            ttl: 64,
            action: GdpAction::Forward as u8,
            src: [0; 32],
            dst: dest,
            last_hop: [0; 32],
            data_len: (payload.len() as u16).into(),
        };

        let header = unsafe { transmute::<_, [u8; size_of::<GdpHeader>()]>(header) };

        buffer.extend(header);
        buffer.extend(payload);

        let len = self.socket.send(&buffer[..])?;
        ensure!(payload.len() == len, "sent only {} bytes", len);
        Ok(())
    }
}
