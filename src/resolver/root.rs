use std::io;
use std::net::UdpSocket;
use std::time::Duration;

use crate::dns::packet::{
    parse_referral,
    IpRecord,
    NsRecord,
    ReferralResponse,
};
use crate::dns::query::{
    build_query,
    TYPE_NS,
};

pub const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4:53",
    "170.247.170.2:53",
    "192.33.4.12:53",
    "199.7.91.13:53",
    "192.203.230.10:53",
    "192.5.5.241:53",
    "192.112.36.4:53",
    "198.97.190.53:53",
    "192.36.148.17:53",
    "192.58.128.30:53",
    "193.0.14.129:53",
    "199.7.83.42:53",
];

pub fn root_servers() -> &'static [&'static str] {
    ROOT_SERVERS
}

pub fn query_root(name: &str) -> io::Result<Vec<u8>> {
    let (_, query) = build_query(name, TYPE_NS);

    let socket =
        UdpSocket::bind("0.0.0.0:0")?;

    socket.set_read_timeout(
        Some(Duration::from_secs(3)),
    )?;

    for server in ROOT_SERVERS {
        if socket
            .send_to(&query, server)
            .is_err()
        {
            continue;
        }

        let mut response = [0u8; 4096];

        match socket.recv_from(&mut response) {
            Ok((size, _)) => {
                return Ok(
                    response[..size].to_vec()
                );
            }

            Err(_) => continue,
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "all root DNS servers failed",
    ))
}

pub fn resolve_tld(
    name: &str,
) -> io::Result<ReferralResponse> {
    let response = query_root(name)?;

    parse_referral(&response)
}
