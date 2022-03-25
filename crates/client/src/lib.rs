mod control;
mod structs;

use std::ffi::CStr;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::raw::c_char;
use std::ptr::slice_from_raw_parts;
use std::str::FromStr;

use anyhow::{ensure, Context, Error, Result};
use pyo3::types::PyModule;
use pyo3::{create_exception, pyclass, pymethods, pymodule, PyErr, PyResult, Python};

pub use crate::control::{ClientCommand, ClientCommands, ClientResponse, ClientResponses};
pub use crate::structs::{GdpAction, GdpHeader, GdpName, MAGIC_NUMBERS};

// https://stackoverflow.com/questions/28127165/how-to-convert-struct-to-u8
unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    &*slice_from_raw_parts((p as *const T) as *const u8, size_of::<T>())
}

#[pyclass]
pub struct GDPClient {
    socket: UdpSocket,
}

create_exception!(
    gdp_client,
    PyGdpClientException,
    pyo3::exceptions::PyException
);

fn py_err(err: Error) -> PyErr {
    PyErr::new::<PyGdpClientException, _>(format!("{:#}", err))
}

#[pymethods]
impl GDPClient {
    #[new]
    fn new_py(sidecar_ip: &str, recv_port: u16) -> PyResult<Self> {
        GDPClient::new(
            Ipv4Addr::from_str(sidecar_ip)
                .context("invalid IP address")
                .map_err(py_err)?,
            recv_port,
        )
        .context("failed to create client")
        .map_err(py_err)
    }

    fn send_packet_py(&self, dest: GdpName, payload: &[u8]) -> PyResult<()> {
        self.send_packet(dest, payload)
            .context("failed to send packet")
            .map_err(py_err)
    }

    fn listen_on_port_py(&self, port: u16) -> PyResult<()> {
        self.listen_on_port(port)
            .context("failed to send control packet")
            .map_err(py_err)
    }
}

impl GDPClient {
    pub fn new(sidecar_ip: Ipv4Addr, recv_port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, recv_port)))
            .context("failed to bind socket")?;
        socket
            .set_broadcast(true)
            .context("failed to set broadcast")?;
        socket
            .connect(SocketAddr::new(sidecar_ip.into(), 31415))
            .context("failed to connect")?;
        Ok(GDPClient { socket })
    }

    #[no_mangle]
    pub unsafe extern "C" fn new_ffi(out: *mut Self, ip: *const c_char, sidecar_port: u16) -> i8 {
        Result::<_, Error>::Ok(())
            .map(|_| CStr::from_ptr(ip))
            .and_then(|str| Ok(CStr::to_str(str)?))
            .and_then(|str| Ok(Ipv4Addr::from_str(str)?))
            .and_then(|ip| Self::new(ip, sidecar_port))
            .map(|client| {
                *out = client;
                0
            })
            .unwrap_or(-1)
    }

    #[no_mangle]
    pub unsafe extern "C" fn send_packet_ffi(
        &self,
        dest: *const GdpName,
        payload: *const u8,
        payload_len: usize,
    ) -> i8 {
        match self.send_packet(*dest, &*slice_from_raw_parts(payload, payload_len)) {
            Ok(_) => 0,
            Err(_) => -1,
        }
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

    pub fn listen_on_port(&self, port: u16) -> Result<()> {
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
}

#[pymodule]
fn gdp_client(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<GDPClient>()?;
    m.add("GdpClientException", py.get_type::<PyGdpClientException>())
}
