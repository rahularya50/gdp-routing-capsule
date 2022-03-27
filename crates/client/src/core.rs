use std::mem::{size_of, transmute};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::ptr::slice_from_raw_parts;
use std::str::FromStr;

use anyhow::{anyhow, bail, ensure, Context, Result};

use crate::{
    ClientCommand, ClientCommands, ClientResponse, ClientResponses, GdpAction, GdpHeader, GdpName,
    MAGIC_NUMBERS,
};

// https://stackoverflow.com/questions/28127165/how-to-convert-struct-to-u8
unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    &*slice_from_raw_parts((p as *const T) as *const u8, size_of::<T>())
}

pub struct GdpClient {
    socket: UdpSocket,
}

impl GdpClient {
    pub fn new(sidecar_ip: Ipv4Addr, recv_port: u16) -> Result<Self> {
        println!("startup!");
        let socket = UdpSocket::bind(SocketAddr::from((
            // Ipv4Addr::from_str("192.168.0.250")?,
            Ipv4Addr::UNSPECIFIED,
            recv_port,
        )))
        .context("failed to bind socket")?;
        socket
            .set_broadcast(true)
            .context("failed to set broadcast")?;
        socket
            .connect(SocketAddr::new(sidecar_ip.into(), 31415))
            .context("failed to connect")?;
        let client = GdpClient { socket };
        client.listen_on_port(recv_port)?;
        let (_header, payload) = loop {
            let (header, payload) = client.recv_with_header()?;
            let action: GdpAction = header.action.try_into()?;
            println!("action: {:?}", action);
            if action != GdpAction::Control {
                continue;
            }
            break (header, payload);
        };
        let ClientResponses { messages } = bincode::deserialize(&*payload)?;
        for msg in messages {
            match msg {
                ClientResponse::PortSet { port } => {
                    ensure!(port == recv_port, "incorrect port set")
                }
                ClientResponse::Error { msg } => bail!(msg.into_owned()),
            }
        }
        Ok(client)
    }

    fn send_header_and_data(&self, header: &GdpHeader, data: &[u8]) -> Result<()> {
        let mut buffer = vec![];

        buffer.extend(unsafe { any_as_u8_slice(header) });
        buffer.extend(data);

        let len = self.socket.send(&buffer)?;
        ensure!(buffer.len() == len, "sent only {} bytes", len);
        Ok(())
    }

    pub fn send_packet(&self, dest: GdpName, payload: &[u8]) -> Result<()> {
        let header = GdpHeader {
            field: MAGIC_NUMBERS.into(),
            ttl: 64,
            action: GdpAction::Forward as u8,
            src: [0; 32],
            dst: dest,
            last_hop: [0; 32],
            data_len: (payload.len() as u16).into(),
        };

        self.send_header_and_data(&header, payload)
    }

    fn listen_on_port(&self, port: u16) -> Result<()> {
        let header = GdpHeader {
            field: MAGIC_NUMBERS.into(),
            action: GdpAction::Control as u8,
            ..Default::default()
        };

        let data = bincode::serialize(&ClientCommands {
            messages: vec![ClientCommand::SetPort { port }],
        })
        .context("failed to serialize commands for transmission")?;

        self.send_header_and_data(&header, &data)
    }

    fn recv_with_header(&self) -> Result<(GdpHeader, Box<[u8]>)> {
        let mut buf = [0u8; 1 << 16];
        loop {
            let (size, _) = self.socket.recv_from(&mut buf)?;
            println!("received with size {size}!");
            ensure!(size > 0, "socket closed unexpectedly");
            // looks like a GDP packet?
            // if u16::from_be_bytes([buf[0], buf[1]]) != MAGIC_NUMBERS {
            //     println!("magic number mismatch: {:x?} {:x?}!", buf[0], buf[1]);
            //     continue;
            // }
            if size < size_of::<GdpHeader>() {
                println!("size smaller than {}", size_of::<GdpHeader>());
                continue;
            }
            // buf[..size].reverse();
            println!("packet: {:?}", &buf[..size]);
            let (header, payload) = buf.split_at(size_of::<GdpHeader>());
            let header: [u8; size_of::<GdpHeader>()] = header.try_into().unwrap();
            let header: GdpHeader = unsafe { transmute(header) };
            println!("magic numbers: {:x?}", header.field);
            return Ok((header, Box::new(payload).to_vec().into_boxed_slice()));
        }
    }
}
