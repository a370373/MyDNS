use std::time::{SystemTime, UNIX_EPOCH};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_HTTPS: u16 = 65;

pub const CLASS_IN: u16 = 1;

pub const EDNS_UDP_SIZE: u16 = 1232;

pub fn build_query(name: &str, record_type: u16) -> (u16, Vec<u8>) {
    build_query_internal(name, record_type, false)
}

pub fn build_query_with_edns(
    name: &str,
    record_type: u16,
) -> (u16, Vec<u8>) {
    build_query_internal(name, record_type, true)
}

fn build_query_internal(
    name: &str,
    record_type: u16,
    edns: bool,
) -> (u16, Vec<u8>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();

    let id = (now.subsec_nanos() & 0xffff) as u16;

    let mut packet = Vec::with_capacity(512);

    // Transaction ID
    packet.extend_from_slice(&id.to_be_bytes());

    // RD=0
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Questions = 1
    packet.extend_from_slice(&1u16.to_be_bytes());

    // Answers = 0
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Authority = 0
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Additional
    packet.extend_from_slice(&(if edns { 1u16 } else { 0u16 }).to_be_bytes());

    // QNAME
    for label in name.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }

    packet.push(0);

    // QTYPE
    packet.extend_from_slice(&record_type.to_be_bytes());

    // QCLASS
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());

    if edns {
        // Root name
        packet.push(0);

        // OPT
        packet.extend_from_slice(&TYPE_OPT.to_be_bytes());

        // UDP payload size
        packet.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());

        // Extended RCODE + version + flags
        packet.extend_from_slice(&0u32.to_be_bytes());

        // RDLEN = 0
        packet.extend_from_slice(&0u16.to_be_bytes());
    }

    (id, packet)
}
