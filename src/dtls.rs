use crate::Ipv4;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use capsule::debug;
use capsule::packets::ip::IpPacket;
use capsule::SizeOf;
use rand::Rng;
use std::fmt;
use std::ptr::NonNull;

use capsule::packets::{Internal, Packet, Udp};

pub struct DTls<T: IpPacket> {
    envelope: Udp<T>,
    header: NonNull<DTlsHeader>,
    offset: usize,
}

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C)]
struct DTlsHeader {
    nonce: [u8; 12], // 96-bit nonce used to decrypt the payload
}

impl<T: IpPacket> DTls<T> {
    #[inline]
    fn header(&self) -> &DTlsHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut DTlsHeader {
        unsafe { self.header.as_mut() }
    }

    #[inline]
    pub fn nonce(&self) -> [u8; 12] {
        self.header().nonce
    }

    #[inline]
    pub fn set_nonce(&mut self, nonce: [u8; 12]) {
        self.header_mut().nonce = nonce;
    }
}

impl<T: IpPacket> fmt::Debug for DTls<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dtls")
            .field("nonce", &self.nonce())
            .finish()
    }
}

impl<T: IpPacket> Packet for DTls<T> {
    type Envelope = Udp<T>;

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        &self.envelope
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        &mut self.envelope
    }

    #[inline]
    fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn header_len(&self) -> usize {
        DTlsHeader::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        DTls {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        let out = DTls {
            envelope,
            header,
            offset,
        };

        Ok(out)
    }

    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, DTlsHeader::size_of())?;
        let header = mbuf.write_data(offset, &DTlsHeader::default())?;

        Ok(DTls {
            envelope,
            header,
            offset,
        })
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }
}

pub fn decrypt_gdp(mut dtls_packet: DTls<Ipv4>) -> Result<DTls<Ipv4>> {
    let key = Key::from_slice(b"an example very very secret key.");
    let cipher = Aes256Gcm::new(key);

    let raw_nonce = dtls_packet.nonce();
    let nonce = Nonce::from_slice(&raw_nonce); // 96-bits; unique per message

    // decrypt the packet
    let data_slice = dtls_packet
        .mbuf()
        .read_data_slice(dtls_packet.payload_offset(), dtls_packet.payload_len())?;
    let data_slice_ref = unsafe { data_slice.as_ref() };

    let decrypted = cipher.decrypt(nonce, data_slice_ref).map_err(|_| {
        debug!("decrypt failed");
        anyhow!("decrypt failed")
    })?;

    // AES generally adds padding. To prevent buffer size creep we must truncate.
    let payload_offset = dtls_packet.payload_offset();
    let decrypted_len = decrypted.len();
    dtls_packet
        .mbuf_mut()
        .truncate(payload_offset + decrypted_len)?;

    let write_offset = dtls_packet.payload_offset();
    dtls_packet
        .mbuf_mut()
        .write_data_slice(write_offset, &decrypted)?;
    Ok(dtls_packet)
}

pub fn encrypt_gdp(mut dtls_packet: DTls<Ipv4>) -> Result<DTls<Ipv4>> {
    let key = Key::from_slice(b"an example very very secret key.");
    let cipher = Aes256Gcm::new(key);

    let nonce = rand::thread_rng().gen::<[u8; 12]>(); // 96-bits; unique per message
    dtls_packet.set_nonce(nonce);
    let nonce = Nonce::from_slice(&nonce);

    // encrypt the packet
    let data_slice = dtls_packet
        .mbuf()
        .read_data_slice(dtls_packet.payload_offset(), dtls_packet.payload_len())?;
    let data_slice_ref = unsafe { data_slice.as_ref() };

    let encrypted = cipher.encrypt(nonce, data_slice_ref).map_err(|_| {
        debug!("encrypt failed");
        anyhow!("encrypt failed")
    })?;

    // rewrite the mbuf with the encrypted packlet
    // AES usually adds a few bytes of padding
    let length_delta = encrypted.len() - dtls_packet.payload_len();
    let end_offset = dtls_packet.payload_offset() + dtls_packet.payload_len();
    if length_delta > 0 {
        dtls_packet.mbuf_mut().extend(end_offset, length_delta)?;
    }

    let write_offset = dtls_packet.payload_offset();
    dtls_packet
        .mbuf_mut()
        .write_data_slice(write_offset, &encrypted)?;
    Ok(dtls_packet)
}
