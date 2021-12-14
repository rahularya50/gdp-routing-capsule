use std::mem;
use std::net::Ipv4Addr;

use anyhow::{anyhow, Result};
use capsule::packets::ip::v4::Ipv4;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signatory::ed25519::{Signature, SigningKey, VerifyingKey, ALGORITHM_ID};
use signatory::pkcs8::{FromPrivateKey, PrivateKeyInfo};
use signatory::signature::{Signer, Verifier};

use crate::gdp::Gdp;
use crate::kvs::{GdpName, Store};
use crate::rib::Route;

#[derive(Hash, Clone, Copy, Deserialize)]
pub struct GdpMeta {
    pub pub_key: [u8; 32], // TODO: compute hash on initialization
}

impl GdpMeta {
    pub fn hash(self) -> GdpName {
        let mut hasher = Sha256::new();
        hasher.update(self.pub_key);
        hasher.finalize().into()
    }
}

#[derive(Clone)]
pub struct GdpRoute {
    pub route: Route,
    pub meta: GdpMeta,
    pub name: GdpName,
    pub verify_key: VerifyingKey,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Certificate {
    pub contents: CertContents,
    signature: SerializableSignature,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
struct SerializableSignature([u8; 32], [u8; 32]);

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
    pub fn verify(&self, meta: GdpMeta) -> Result<()> {
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

#[derive(Serialize, Deserialize, Debug)]
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

    fn owner(&self) -> GdpName {
        match *self {
            CertContents::RtCert(RtCert { base, .. }) => base,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub enum CertDest {
    GdpName(GdpName),
    IpAddr(Ipv4Addr),
}

impl GdpRoute {
    pub fn gdp_name_of_index(index: u8) -> GdpName {
        let (_, verify_key) = gen_keypair_u8(index).unwrap();
        GdpMeta {
            pub_key: verify_key.to_bytes(),
        }
        .hash()
    }

    pub fn private_key_of_index(index: u8) -> SigningKey {
        gen_keypair_u8(index).unwrap().0
    }

    pub fn from_serial_entry(index: u8, route: Route) -> Self {
        let (_, verify_key) = gen_keypair_u8(index).unwrap();
        let meta = GdpMeta {
            pub_key: verify_key.to_bytes(),
        };
        GdpRoute {
            meta,
            route,
            name: meta.hash(),
            verify_key,
        }
    }
}

fn gen_keypair_u8(seed: u8) -> Result<(SigningKey, VerifyingKey)> {
    let mut arr = [0u8; 32];
    arr[0] = seed; // TODO: load a u8 from the toml
    gen_keypair(&arr)
}

fn gen_keypair(seed: &[u8; 32]) -> Result<(SigningKey, VerifyingKey)> {
    let signing_key =
        SigningKey::from_pkcs8_private_key_info(PrivateKeyInfo::new(ALGORITHM_ID, seed))?;
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

fn sign(key: &SigningKey, msg: &[u8]) -> Signature {
    Signature::new(key.sign(msg).to_bytes())
}

pub fn test_signatures(msg: &'_ [u8]) -> Result<&'_ [u8]> {
    let seed = [0u8; 32];
    let (sign_key, verify_key) = gen_keypair(&seed)?;
    let verify_bytes = verify_key.to_bytes();
    let verify_key = VerifyingKey::from_bytes(&verify_bytes)?;
    let sig = sign(&sign_key, msg);
    let enc_sig = sig.to_bytes();
    let dec_sig = Signature::new(enc_sig);
    verify_key.verify(msg, &dec_sig)?;
    Ok(msg)
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
        if debug {
            println!("{} received packet with certificates {:?}", nic_name, certs);
        }
        let mut pos = packet.src();
        for cert in certs.certificates {
            if cert.contents.owner() != pos {
                return false;
            }
            match cert.contents {
                CertContents::RtCert(RtCert {
                    proxy: CertDest::GdpName(proxy),
                    ..
                }) => pos = proxy,
                _ => return false,
            }
        }
        if pos != gdp_name {
            return false;
        }
        true
    } else {
        false
    }
}
