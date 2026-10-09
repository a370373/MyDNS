use std::io;

use crate::dns::packet::{
    parse_referral,
    IpRecord,
    NsRecord,
    ReferralResponse,
};
use crate::dns::query::{
    build_query,
    exchange,
    TYPE_NS,
    UPSTREAM_TIMEOUT,
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
    let (id, query) = build_query(name, TYPE_NS);

    for server in ROOT_SERVERS {
        let address = server.trim_end_matches(":53");

        if let Ok(response) =
            exchange(address, &query, id, UPSTREAM_TIMEOUT)
        {
            if parse_referral(&response).is_ok() {
                return Ok(response);
            }
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
