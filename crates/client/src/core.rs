use std::mem::{size_of, transmute};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::ptr::slice_from_raw_parts;

use anyhow::{bail, ensure, Context, Result};

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
    sidecar_addr: SocketAddr,
    port: u16,
}

impl GdpClient {
    pub fn new(sidecar_ip: Ipv4Addr, recv_port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, recv_port)))
            .context("failed to bind socket")?;
        socket
            .set_broadcast(true)
            .context("failed to set broadcast")?;
        let mut client = GdpClient {
            socket,
            port: 0,
            sidecar_addr: SocketAddr::new(sidecar_ip.into(), 25000),
        };
        client.listen_on_port(recv_port)?;
        let payload = loop {
            let (header, payload) = client.recv_with_header()?;
            let action: GdpAction = header.action.try_into()?;
            if action != GdpAction::Control {
                // drop data packets received during setup
                continue;
            }
            break payload;
        };
        client.process_control_payload(&payload)?;
        ensure!(recv_port == client.port, "incorrect port set in sidecar");
        Ok(client)
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

    pub fn recv_from(&mut self) -> Result<(GdpName, Box<[u8]>)> {
        loop {
            let (header, payload) = self.recv_with_header()?;
            match GdpAction::try_from(header.action)? {
                GdpAction::Control => self.process_control_payload(&payload)?,
                GdpAction::Forward => return Ok((header.src, payload)),
                action => bail!("unexpected packet action type: {:?}", action),
            };
        }
    }

    fn recv_with_header(&self) -> Result<(GdpHeader, Box<[u8]>)> {
        let mut buf = [0u8; 1 << 16];
        loop {
            let (size, _) = self.socket.recv_from(&mut buf)?;
            ensure!(size > 0, "socket closed unexpectedly");
            // looks like a GDP packet?
            if u16::from_be_bytes([buf[0], buf[1]]) != MAGIC_NUMBERS
                || size < size_of::<GdpHeader>()
            {
                continue;
            }
            let buf = &buf[..size];
            let (header, payload) = buf.split_at(size_of::<GdpHeader>());
            let header: [u8; size_of::<GdpHeader>()] = header.try_into().unwrap();
            let header: GdpHeader = unsafe { transmute(header) };
            return Ok((header, payload.to_vec().into_boxed_slice()));
        }
    }

    fn send_header_and_data(&self, header: &GdpHeader, data: &[u8]) -> Result<()> {
        let mut buffer = vec![];

        buffer.extend(unsafe { any_as_u8_slice(header) });
        buffer.extend(data);

        let len = self.socket.send_to(&buffer, self.sidecar_addr)?;
        ensure!(buffer.len() == len, "sent only {} bytes", len);
        Ok(())
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

    fn process_control_payload(&mut self, payload: &[u8]) -> Result<()> {
        let ClientResponses { messages } = bincode::deserialize(&*payload)?;
        for msg in messages {
            match msg {
                ClientResponse::PortSet { port } => self.port = port,
                ClientResponse::Error { msg } => bail!(msg.into_owned()),
            }
        }
        Ok(())
    }
}
