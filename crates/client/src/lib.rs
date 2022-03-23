mod structs;

use std::intrinsics::transmute;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::ptr::slice_from_raw_parts;
use std::str::FromStr;

use anyhow::{ensure, Result};
use pyo3::types::PyModule;
use pyo3::{create_exception, pyclass, pymethods, pymodule, PyErr, PyResult, Python};

pub use crate::structs::{GdpAction, GdpHeader, GdpName, MAGIC_NUMBERS};

#[pyclass]
pub struct GDPClient {
    socket: UdpSocket,
}

create_exception!(
    gdp_client,
    PyGdpClientException,
    pyo3::exceptions::PyException
);

fn py_err(msg: String) -> PyErr {
    PyErr::new::<PyGdpClientException, _>(msg)
}

#[pymethods]
impl GDPClient {
    #[new]
    fn new_py(sidecar_ip: &str, recv_port: u16) -> PyResult<Self> {
        GDPClient::new(
            Ipv4Addr::from_str(sidecar_ip).map_err(|err| {
                py_err(format!(
                    "Invalid IP address {} ({})",
                    sidecar_ip,
                    err.to_string()
                ))
            })?,
            recv_port,
        )
        .map_err(|err| py_err(format!("Failed to create client ({})", err.to_string())))
    }

    #[no_mangle]
    fn send_packet_py(&self, dest: GdpName, payload: &[u8]) -> PyResult<()> {
        self.send_packet(dest, payload)
            .map_err(|err| py_err(format!("Failed to send packet ({})", err.to_string())))
    }
}

impl GDPClient {
    pub fn new(sidecar_ip: Ipv4Addr, recv_port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], recv_port)))?;
        socket.connect(SocketAddr::new(sidecar_ip.into(), 31415))?;
        Ok(GDPClient { socket })
    }

    // #[no_mangle]
    // pub unsafe extern "C" fn new_ffi(out: *mut Self, lib_port: u16, sidecar_port: u16) -> i8 {
    //     match Self::new(lib_port, sidecar_port) {
    //         Ok(client) => {
    //             *out = client;
    //             0
    //         }
    //         Err(_) => -1,
    //     }
    // }

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
        ensure!(buffer.len() == len, "sent only {} bytes", len);
        Ok(())
    }
}

#[pymodule]
fn gdp_client(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<GDPClient>()?;
    m.add("GdpClientException", py.get_type::<PyGdpClientException>())
}
