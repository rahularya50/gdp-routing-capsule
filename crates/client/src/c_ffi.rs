use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::os::raw::c_char;
use std::ptr::slice_from_raw_parts;
use std::str::FromStr;

use anyhow::{Error, Result};

use crate::core::GdpClient;
use crate::structs::GdpName;

struct CGdpClient(GdpClient);

impl CGdpClient {
    #[no_mangle]
    pub unsafe extern "C" fn new(out: *mut Self, ip: *const c_char, sidecar_port: u16) -> i8 {
        Result::<_, Error>::Ok(())
            .map(|_| CStr::from_ptr(ip))
            .and_then(|str| Ok(CStr::to_str(str)?))
            .and_then(|str| Ok(Ipv4Addr::from_str(str)?))
            .and_then(|ip| GdpClient::new(ip, sidecar_port))
            .map(|client| {
                *out = CGdpClient(client);
                0
            })
            .unwrap_or(-1)
    }

    #[no_mangle]
    pub unsafe extern "C" fn send_packet(
        &self,
        dest: *const GdpName,
        payload: *const u8,
        payload_len: usize,
    ) -> i8 {
        match self
            .0
            .send_packet(*dest, &*slice_from_raw_parts(payload, payload_len))
        {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }
}
