use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

fn random_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // RandomState is seeded from the OS, so the id is unpredictable.
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(nanos);
    hasher.finish() as u16
}

/// Send `query` to `server:53` from a fresh socket and return the first
/// reply that comes from that server, echoes `id` and has QR set.
/// Late or spoofed datagrams are ignored until the timeout expires.
pub fn exchange(
    server: &str,
    query: &[u8],
    id: u16,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let ip: IpAddr = server.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid upstream address",
        )
    })?;

    exchange_with(SocketAddr::new(ip, 53), query, id, timeout)
}

pub fn exchange_with(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind)?;

    // connect() makes the OS drop datagrams from any other source.
    socket.connect(server)?;
    socket.send(query)?;

    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 4096];

    loop {
        let remaining =
            deadline.saturating_duration_since(Instant::now());

        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream timed out",
            ));
        }

        socket.set_read_timeout(Some(remaining))?;

        let size = socket.recv(&mut buffer)?;

        if size >= 12
            && buffer[..2] == id.to_be_bytes()
            && buffer[2] & 0x80 != 0
        {
            return Ok(buffer[..size].to_vec());
        }
    }
}

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
    let id = random_id();

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
