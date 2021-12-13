use anyhow::Result;
use signatory::ed25519::{Signature, SigningKey, VerifyingKey, ALGORITHM_ID};
use signatory::pkcs8::{FromPrivateKey, PrivateKeyInfo};
use signatory::signature::{Signer, Verifier};

use crate::gdp::GdpMeta;
use crate::kvs::GdpName;
use crate::rib::Route;

#[derive(Clone)]
pub struct GdpRoute {
    pub route: Route,
    pub meta: GdpMeta,
    pub name: GdpName,
    pub verify_key: VerifyingKey,
}

impl GdpRoute {
    pub fn gdp_name_of_index(index: u8) -> GdpName {
        let (_, verify_key) = gen_keypair_u8(index).unwrap();
        GdpMeta {
            pub_key: verify_key.to_bytes(),
        }
        .hash()
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
