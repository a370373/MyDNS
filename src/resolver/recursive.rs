use std::io;
use std::net::UdpSocket;
use std::time::Duration;

use crate::dns::packet::{
    parse_authoritative,
    parse_referral,
    IpRecord,
    ReferralResponse,
};

use crate::dns::record::{
    CnameRecord,
    DnsRecord,
    HttpsRecord,
};
use crate::dns::query::{
    build_query,
    TYPE_A,
    TYPE_AAAA,
    TYPE_HTTPS,
    TYPE_NS,
};

#[derive(Debug)]
pub struct Resolution {
    pub records: Vec<DnsRecord>,
    pub rcode: u8,
}

pub fn find_tld_servers(
    domain: &str,
) -> io::Result<ReferralResponse> {
    crate::resolver::root::resolve_tld(domain)
}

pub fn query_tld(
    tld_servers: &[IpRecord],
    domain: &str,
) -> io::Result<ReferralResponse> {
    let (_, query) =
        build_query(domain, TYPE_NS);

    let socket =
        UdpSocket::bind("0.0.0.0:0")?;

    socket.set_read_timeout(
        Some(Duration::from_secs(3)),
    )?;

    let mut last_error = None;

    for server in tld_servers {
        let address =
            format!("{}:53", server.address);

        if let Err(error) =
            socket.send_to(&query, &address)
        {
            last_error = Some(error);
            continue;
        }

        let mut response = [0u8; 4096];

        let size =
            match socket.recv_from(&mut response) {
                Ok((size, _)) => size,

                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };

        let parsed =
            match parse_referral(&response[..size]) {
                Ok(parsed) => parsed,

                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };

        /*
         * Preserve the DNS RCODE.
         *
         * RCODE 3 (NXDOMAIN) is a valid DNS result,
         * not a transport/resolver failure.
         */
        if parsed.rcode != 0 {
            return Ok(parsed);
        }

        /*
         * Some TLD referrals contain NS records but
         * no glue A/AAAA records.
         *
         * Resolve the NS hostname itself to obtain
         * the authoritative server address.
         */
        if parsed.ip_records.is_empty()
            && !parsed.ns_records.is_empty()
        {
            let mut resolved = parsed.clone();

            for ns in &parsed.ns_records {
                let ns_name = ns.target.trim_end_matches('.');

                println!(
                    "No TLD glue for {}. Resolving NS {}",
                    domain,
                    ns_name
                );

                let ns_root =
                    match find_tld_servers(ns_name) {
                        Ok(result) => result,

                        Err(_) => continue,
                    };

                if ns_root.rcode != 0 {
                    continue;
                }

                if ns_root.ip_records.is_empty() {
                    continue;
                }

                let ns_tld =
                    match query_tld(
                        &ns_root.ip_records,
                        ns_name,
                    ) {
                        Ok(result) => result,

                        Err(_) => continue,
                    };

                if ns_tld.rcode != 0 {
                    continue;
                }

                if ns_tld.ip_records.is_empty() {
                    continue;
                }

                if let Ok(ns_a) =
                    resolve_authoritative(
                        &ns_tld.ip_records,
                        ns_name,
                        TYPE_A,
                    )
                {
                    for record in ns_a.records {
                        if let DnsRecord::A(record) = record {
                            resolved.ip_records.push(
                                IpRecord {
                                    name: record.name,
                                    address: record.address,
                                },
                            );
                        }
                    }
                }

                if let Ok(ns_aaaa) =
                    resolve_authoritative(
                        &ns_tld.ip_records,
                        ns_name,
                        TYPE_AAAA,
                    )
                {
                    for record in ns_aaaa.records {
                        if let DnsRecord::AAAA(record) = record {
                            resolved.ip_records.push(
                                IpRecord {
                                    name: record.name,
                                    address: record.address,
                                },
                            );
                        }
                    }
                }

                if !resolved.ip_records.is_empty() {
                    println!(
                        "Resolved authoritative NS {}",
                        ns_name
                    );

                    return Ok(resolved);
                }
            }
        }

        return Ok(parsed);
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "all TLD DNS servers failed",
        )
    }))
}

pub fn query_authoritative(
    authoritative_servers: &[IpRecord],
    domain: &str,
    record_type: u16,
) -> io::Result<Resolution> {
    let (_, query) =
        build_query(domain, record_type);

    let socket =
        UdpSocket::bind("0.0.0.0:0")?;

    socket.set_read_timeout(
        Some(Duration::from_secs(3)),
    )?;

    let mut last_error = None;

    for server in authoritative_servers {
        let address =
            format!("{}:53", server.address);

        if let Err(error) =
            socket.send_to(&query, &address)
        {
            last_error = Some(error);
            continue;
        }

        let mut response = [0u8; 4096];

        let size =
            match socket.recv_from(&mut response) {
                Ok((size, _)) => size,

                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };

        let parsed =
            match parse_authoritative(
                &response[..size],
            ) {
                Ok(parsed) => parsed,

                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };

        return Ok(Resolution {
            records: parsed.records,
            rcode: parsed.rcode,
        });
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "all authoritative DNS servers failed",
        )
    }))
}


const MAX_CNAME_DEPTH: usize = 16;

pub fn resolve_authoritative(
    authoritative_servers: &[IpRecord],
    domain: &str,
    record_type: u16,
) -> io::Result<Resolution> {
    resolve_authoritative_recursive(
        authoritative_servers,
        domain,
        record_type,
        0,
    )
}

fn resolve_authoritative_recursive(
    authoritative_servers: &[IpRecord],
    domain: &str,
    record_type: u16,
    depth: usize,
) -> io::Result<Resolution> {
    if depth >= MAX_CNAME_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CNAME recursion limit exceeded",
        ));
    }

    let resolution =
        match record_type {
            TYPE_A | TYPE_AAAA | TYPE_HTTPS => {
                query_authoritative(
                    authoritative_servers,
                    domain,
                    record_type,
                )?
            }

            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported record type",
                ));
            }
        };

    /*
     * Check whether the authoritative response already
     * contains the requested record type.
     */
    let has_requested_record =
        resolution.records.iter().any(|record| {
            record.record_type() == record_type
        });

    if has_requested_record {
        return Ok(resolution);
    }

    /*
     * The authoritative server may return HTTPS directly.
     * Keep it as a complete answer.
     */
    if resolution.records.iter().any(|record| {
        matches!(record, DnsRecord::Https(_))
    }) {
        return Ok(resolution);
    }

    /*
     * The authoritative server returned a CNAME.
     *
     * Restart resolution from the root for the canonical
     * target because the target may belong to a completely
     * different DNS zone.
     */
    let cname = resolution.records.iter().find_map(|record| {
        match record {
            DnsRecord::Cname(cname) => Some(cname.clone()),
            _ => None,
        }
    });

    if let Some(cname) = cname {
        let target =
            cname.target.trim_end_matches('.').to_string();

        println!(
            "CNAME: {} -> {}",
            domain,
            target
        );

        let root =
            find_tld_servers(&target)?;

        if root.rcode != 0 {
            return Ok(Resolution {
                records: vec![
                    DnsRecord::Cname(cname)
                ],
                rcode: root.rcode,
            });
        }

        if root.ip_records.is_empty() {
            return Ok(Resolution {
                records: vec![
                    DnsRecord::Cname(cname)
                ],
                rcode: 0,
            });
        }

        let tld =
            query_tld(
                &root.ip_records,
                &target,
            )?;

        if tld.rcode != 0 {
            return Ok(Resolution {
                records: vec![
                    DnsRecord::Cname(cname)
                ],
                rcode: tld.rcode,
            });
        }

        if tld.ip_records.is_empty() {
            return Ok(Resolution {
                records: vec![
                    DnsRecord::Cname(cname)
                ],
                rcode: 0,
            });
        }

        let mut final_resolution =
            resolve_authoritative_recursive(
                &tld.ip_records,
                &target,
                record_type,
                depth + 1,
            )?;

        /*
         * Preserve the CNAME chain so the final response
         * can still expose the canonical mapping.
         */
        final_resolution.records.insert(
            0,
            DnsRecord::Cname(cname),
        );

        return Ok(final_resolution);
    }

    Ok(resolution)
}
