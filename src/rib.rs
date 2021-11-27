use crate::dtls::DTls;
use crate::gdp::Gdp;
use crate::gdp::GdpAction;
use crate::kvs::GdpName;
use crate::kvs::Store;
use crate::pipeline;
use crate::utils::BroadcastMacAddr;
use crate::GdpPipeline;
use anyhow::{anyhow, Result};
use capsule::batch::Batch;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Udp;
use capsule::packets::{Ethernet, Packet};
use capsule::Mbuf;
use serde::Deserialize;
use signatory::ed25519::Signature;
use signatory::ed25519::SigningKey;
use signatory::ed25519::VerifyingKey;
use signatory::ed25519::ALGORITHM_ID;
use signatory::pkcs8::FromPrivateKey;
use signatory::pkcs8::PrivateKeyInfo;
use signatory::signature::Signer;
use signatory::signature::Verifier;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;

// static RIB_MAC: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0xFF, 0xFF, 0x00);
const RIB_IP: Ipv4Addr = Ipv4Addr::new(10, 100, 1, 10);
const RIB_PORT: u16 = 27182;

pub fn create_rib_request(
    message: Mbuf,
    key: GdpName,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    _store: Store,
) -> Result<Gdp<Ipv4>> {
    let mut message = message.push::<Ethernet>()?;
    message.set_src(src_mac);
    message.set_dst(MacAddr::broadcast());

    let mut message = message.push::<Ipv4>()?;
    message.set_src(src_ip);
    message.set_dst(RIB_IP);

    let mut message = message.push::<Udp<Ipv4>>()?;
    message.set_src_port(RIB_PORT);
    message.set_dst_port(RIB_PORT);

    let message = message.push::<DTls<Ipv4>>()?;

    let mut message = message.push::<Gdp<Ipv4>>()?;

    message.set_action(GdpAction::RibGet);
    message.set_key(key);

    message.reconcile_all();

    Ok(message)
}

pub fn handle_rib_reply(packet: &Gdp<Ipv4>, store: Store) -> Result<()> {
    store.with_mut_contents(|store| {
        store
            .forwarding_table
            .insert(packet.key(), packet.value().into())
    });
    Ok(())
}

fn handle_rib_query(packet: &Gdp<Ipv4>, routes: &Routes) -> Result<Gdp<Ipv4>> {
    let dtls = packet.envelope();
    let udp = dtls.envelope();
    let ipv4 = udp.envelope();
    let ethernet = ipv4.envelope();

    let out = Mbuf::new()?;
    let mut out = out.push::<Ethernet>()?;
    out.set_src(ethernet.dst());
    out.set_dst(ethernet.src());

    let mut out = out.push::<Ipv4>()?;
    out.set_src(ipv4.dst());
    out.set_dst(ipv4.src());

    let mut out = out.push::<Udp<Ipv4>>()?;
    out.set_src_port(udp.dst_port());
    out.set_dst_port(udp.src_port());

    let out = out.push::<DTls<Ipv4>>()?;

    let mut out = out.push::<Gdp<Ipv4>>()?;
    out.set_action(GdpAction::RibReply);
    out.set_key(packet.key());
    out.set_value(
        routes
            .routes
            .get(&packet.key().to_string())
            .ok_or(anyhow!("GDPName not found!"))?
            .clone()
            .into(),
    );
    out.reconcile_all();
    Ok(out)
}

pub fn rib_pipeline() -> Result<impl GdpPipeline + Copy> {
    let routes: &Routes = Box::leak(Box::new(load_routes("routes.toml")?));
    Ok(pipeline! {
        GdpAction::RibGet => |group| {
            group.replace(move |packet| handle_rib_query(packet, routes))
        }
        _ => |group| {group.filter(|_| false)}
    })
}

#[derive(Deserialize)]
struct Routes {
    routes: HashMap<String, Ipv4Addr>,
}

fn load_routes(path: &str) -> Result<Routes> {
    let content = fs::read_to_string(path)?;
    Ok(toml::from_str(&content)?)
}

fn gen_signing_key() -> Result<SigningKey> {
    Ok(SigningKey::from_pkcs8_private_key_info(
        PrivateKeyInfo::new(ALGORITHM_ID, &[0u8; 32]),
    )?)
}

pub fn gen_verifying_key() -> Result<VerifyingKey> {
    Ok(gen_signing_key()?.verifying_key())
}

pub fn test_signatures<'a>(_msg: &'a [u8]) -> Result<&'a [u8]> {
    let msg = b"Hello, world!";
    let signature = gen_signing_key()?.sign(msg);
    let encoded_signature = signature.to_bytes();
    let decoded_signature = Signature::new(encoded_signature);
    gen_verifying_key()?.verify(msg, &decoded_signature)?;
    Ok(msg)
}
