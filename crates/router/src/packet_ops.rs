use anyhow::Result;
use capsule::packets::Packet;

pub fn get_payload(packet: &impl Packet) -> Result<&[u8]> {
    let data = packet
        .mbuf()
        .read_data_slice(packet.payload_offset(), packet.payload_len())?;
    Ok(unsafe { data.as_ref() })
}

pub fn set_payload(packet: &mut impl Packet, data: &[u8]) -> Result<()> {
    packet.remove_payload()?;
    let payload_offset = packet.payload_offset();
    packet.mbuf_mut().extend(payload_offset, data.len())?;
    packet.mbuf_mut().write_data_slice(payload_offset, data)?;
    Ok(())
}
