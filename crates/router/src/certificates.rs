use std::mem;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use capsule::packets::Packet;
use gdp_client::GdpName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signatory::ed25519::{Signature, SigningKey, VerifyingKey, ALGORITHM_ID};
use signatory::pkcs8::{FromPrivateKey, PrivateKeyInfo};
use signatory::signature::{Signer, Verifier};

use crate::gdp::Gdp;
use crate::kvs::Store;

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
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
        if meta.hash() != *self.contents.owner() {
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

    pub fn owner(&self) -> &GdpName {
        match *self {
            CertContents::RtCert(RtCert { ref base, .. }) => base,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RtCert {
    pub base: GdpName,
    pub proxy: CertDest,
    pub expiration_time: u64,

    /*
        Whether we can send messages to the base via the proxy,
        or if we should only accept messages *from* the proxy as being via the base
    */
    pub bidirectional: bool,
}

impl RtCert {
    pub fn new_wrapped(
        base: GdpMeta,
        private_key: [u8; 32],
        proxy: CertDest,
        bidirectional: bool,
    ) -> Result<Certificate> {
        let contents = CertContents::RtCert(RtCert {
            base: base.hash(),
            proxy,
            expiration_time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 4 * 60 * 60,
            bidirectional,
        });
        let signing_key = SigningKey::from_pkcs8_private_key_info(PrivateKeyInfo::new(
            ALGORITHM_ID,
            &private_key,
        ))?;
        let signature = contents.sign(signing_key)?.into();
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

pub fn check_packet_certificates<T: Packet>(
    gdp_name: GdpName,
    packet: &Gdp<T>,
    store: &Store,
    mut needed_metas: Option<&mut Vec<GdpName>>,
    nic_name: &str,
    debug: bool,
) -> bool {
    let mut ok = true;
    if let Ok(certs) = packet.get_certs() {
        if debug {
            println!("{} received packet with certificates {:?}", nic_name, certs);
        }
        let mut pos = packet.src();
        for cert in certs.certificates {
            if *cert.contents.owner() != pos {
                println!("owner mismatch {:?} {:?}", cert.contents.owner(), pos);
                return false;
            }
            if let Some(metadata) = store.gdp_metadata.get_unchecked(&pos) {
                if cert.verify(&metadata).is_err() {
                    println!("incorrect signature");
                    return false;
                }
            } else if let Some(ref mut needed_metas) = needed_metas {
                needed_metas.push(pos);
                ok = false;
            } else {
                return false;
            }
            match cert.contents {
                CertContents::RtCert(RtCert {
                    proxy: CertDest::GdpName(proxy),
                    ..
                }) => pos = proxy,
                _ => {
                    println!("not a gdpname rtcert");
                    return false;
                }
            }
        }
        if pos != gdp_name {
            println!("didn't end up at target");
            return false;
        }
        ok
    } else {
        false
    }
}
