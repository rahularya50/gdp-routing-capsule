use std::net::Ipv4Addr;
use std::str::FromStr;

use anyhow::{Context, Error};
use pyo3::types::PyModule;
use pyo3::{create_exception, pyclass, pymethods, pymodule, PyErr, PyResult, Python};

use crate::core::GdpClient;
use crate::structs::GdpName;

#[pyclass]
struct PyGdpClient(GdpClient);

create_exception!(
    gdp_client,
    PyGdpClientException,
    pyo3::exceptions::PyException
);

fn py_err(err: Error) -> PyErr {
    PyErr::new::<PyGdpClientException, _>(format!("{:#}", err))
}

#[pymethods]
impl PyGdpClient {
    #[new]
    fn new(sidecar_ip: &str, recv_port: u16) -> PyResult<Self> {
        GdpClient::new(
            Ipv4Addr::from_str(sidecar_ip)
                .context("invalid IP address")
                .map_err(py_err)?,
            recv_port,
        )
        .context("failed to create client")
        .map(PyGdpClient)
        .map_err(py_err)
    }

    fn send_packet(&self, dest: GdpName, payload: &[u8]) -> PyResult<()> {
        self.0
            .send_packet(dest, payload)
            .context("failed to send packet")
            .map_err(py_err)
    }
}

#[pymodule]
fn gdp_client(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyGdpClient>()?;
    m.add("GdpClientException", py.get_type::<PyGdpClientException>())
}
