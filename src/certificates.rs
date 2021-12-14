use std::mem;
use std::net::Ipv4Addr;

use anyhow::{anyhow, Result};
use capsule::packets::ip::v4::Ipv4;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signatory::ed25519::{Signature, SigningKey, VerifyingKey};
use signatory::signature::{Signer, Verifier};

use crate::gdp::Gdp;
use crate::kvs::{GdpName, Store};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct GdpMeta {
    pub pub_key: [u8; 32], // TODO: compute hash on initialization
}

impl GdpMeta {
    pub fn hash(&self) -> GdpName {
        let mut hasher = Sha256::new();
        hasher.update(self.pub_key);
        hasher.finalize().into()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Certificate {
    pub contents: CertContents,
    signature: SerializableSignature,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub struct SerializableSignature([u8; 32], [u8; 32]);

impl From<[u8; 64]> for SerializableSignature {
    fn from(x: [u8; 64]) -> SerializableSignature {
        unsafe { mem::transmute(x) }
    }
}

impl From<SerializableSignature> for [u8; 64] {
    fn from(x: SerializableSignature) -> [u8; 64] {
        unsafe { mem::transmute(x) }
    }
}

impl Certificate {
    pub fn verify(&self, meta: &GdpMeta) -> Result<()> {
        if meta.hash() != self.contents.owner() {
            return Err(anyhow!("public key does not match gdpname"));
        }
        let verifying_key = VerifyingKey::from_bytes(&meta.pub_key)?;
        Ok(verifying_key.verify(
            &self.contents.serialized()?,
            &Signature::new(self.signature.into()),
        )?)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum CertContents {
    RtCert(RtCert),
}

impl CertContents {
    fn serialized(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&self)?)
    }

    fn sign(&self, signing_key: SigningKey) -> Result<[u8; 64]> {
        Ok(signing_key.sign(&bincode::serialize(&self)?).to_bytes())
    }

    pub fn owner(&self) -> GdpName {
        match *self {
            CertContents::RtCert(RtCert { base, .. }) => base,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RtCert {
    pub base: GdpName,
    pub proxy: CertDest,

    /*
        Whether we can send messages to the base via the proxy,
        or if we should only accept messages *from* the proxy as being via the base
    */
    pub bidirectional: bool,
}

impl RtCert {
    pub fn new_wrapped(
        base: GdpMeta,
        private_key: SigningKey,
        proxy: CertDest,
        bidirectional: bool,
    ) -> Result<Certificate> {
        let contents = CertContents::RtCert(RtCert {
            base: base.hash(),
            proxy,
            bidirectional,
        });
        let signature = contents.sign(private_key)?.into();
        Ok(Certificate {
            contents,
            signature,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum CertDest {
    GdpName(GdpName),
    IpAddr(Ipv4Addr),
}

pub fn check_packet_certificates(
    gdp_name: GdpName,
    packet: &Gdp<Ipv4>,
    _store: &Store,
    _needed_metas: Option<&mut Vec<GdpName>>,
    nic_name: &str,
    debug: bool,
) -> bool {
    if let Ok(certs) = packet.get_certs() {
        // if debug {
        //     println!("{} received packet with certificates {:?}", nic_name, certs);
        // }
        // let mut pos = packet.src();
        // for cert in certs.certificates {
        //     if cert.contents.owner() != pos {
        //         return false;
        //     }
        //     match cert.contents {
        //         CertContents::RtCert(RtCert {
        //             proxy: CertDest::GdpName(proxy),
        //             ..
        //         }) => pos = proxy,
        //         _ => return false,
        //     }
        // }
        // if pos != gdp_name {
        //     return false;
        // }
        true
    } else {
        false
    }
}
