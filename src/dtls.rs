use crate::Ipv4;
use aes_gcm::aead::{Aead, Buffer, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};

use capsule::packets::Packet;
use capsule::packets::Udp;

pub fn decrypt_gdp(mut udp_packet: Udp<Ipv4>) -> Result<Udp<Ipv4>> {
    let key = Key::from_slice(b"an example very very secret key.");
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

    // decrypt the packet
    let data_slice = udp_packet.mbuf().read_data_slice(
        udp_packet.header_len(),
        udp_packet.len() - udp_packet.header_len(),
    )?;
    let data_slice_ref = unsafe { data_slice.as_ref() };

    let decrypted = cipher.decrypt(nonce, data_slice_ref).expect("failed!");

    // rewrite the mbuf with the decrypted packlet
    let header_length = udp_packet.header_len();
    let total_length = udp_packet.len();
    let length_delta = decrypted.len() - (total_length - header_length);
    if length_delta > 0 {
        udp_packet.mbuf_mut().extend(total_length, length_delta)?;
    }
    udp_packet
        .mbuf_mut()
        .write_data_slice(header_length, &decrypted)?;
    Ok(udp_packet)
}

pub fn encrypt_gdp(mut udp_packet: Udp<Ipv4>) -> Result<Udp<Ipv4>> {
    let key = Key::from_slice(b"an example very very secret key.");
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

    // encrypt the packet
    let data_slice = udp_packet.mbuf().read_data_slice(
        udp_packet.header_len(),
        udp_packet.len() - udp_packet.header_len(),
    )?;
    let data_slice_ref = unsafe { data_slice.as_ref() };

    let encrypted = cipher
        .encrypt(nonce, data_slice_ref)
        .map_err(|_| anyhow!("encrypt failed"))?;

    // rewrite the mbuf with the decrypted packlet
    let header_length = udp_packet.header_len();
    let total_length = udp_packet.len();
    let length_delta = encrypted.len() - (total_length - header_length);
    if length_delta > 0 {
        udp_packet.mbuf_mut().extend(total_length, length_delta)?;
    }
    udp_packet
        .mbuf_mut()
        .write_data_slice(header_length, &encrypted)?;
    Ok(udp_packet)
}
