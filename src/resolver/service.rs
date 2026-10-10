use std::io;
use std::sync::{Arc, Mutex};

use crate::dns::packet::{
    build_error_response,
    build_response_with_cname,
    build_response_with_https,
    IpRecord,
};
use crate::dns::query::{
    CLASS_IN,
    TYPE_A,
    TYPE_AAAA,
    TYPE_HTTPS,
};
use crate::dns::record::DnsRecord;
use crate::resolver::cache::DnsCache;
use crate::resolver::recursive::{
    find_tld_servers,
    query_tld,
    resolve_authoritative,
};

#[derive(Clone)]
pub struct DnsService {
    cache: Arc<Mutex<DnsCache>>,
}

impl DnsService {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(
                Mutex::new(DnsCache::new())
            ),
        }
    }

    pub fn handle_query(
        &self,
        request: &[u8],
    ) -> io::Result<Vec<u8>> {
        if request.len() < 12 {
            return build_error_response(
                request,
                1,
            );
        }

        // A datagram that is itself a response is not a query.
        if request[2] & 0x80 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a query",
            ));
        }

        // Only standard queries (opcode 0) are implemented.
        if (request[2] >> 3) & 0x0f != 0 {
            return build_error_response(request, 4);
        }

        let mut pos = 12;

        let domain =
            match crate::dns::packet::read_name(
                request,
                &mut pos,
            ) {
                Ok(name) => name,

                Err(_) => {
                    return build_error_response(
                        request,
                        1,
                    );
                }
            };

        if pos + 4 > request.len() {
            return build_error_response(
                request,
                1,
            );
        }

        let record_type =
            u16::from_be_bytes([
                request[pos],
                request[pos + 1],
            ]);

        let class =
            u16::from_be_bytes([
                request[pos + 2],
                request[pos + 3],
            ]);

        println!(
            "Query: {} {}",
            domain,
            record_type
        );

        if class != CLASS_IN {
            return build_error_response(
                request,
                4,
            );
        }

        if record_type != TYPE_A
            && record_type != TYPE_AAAA
            && record_type != TYPE_HTTPS
        {
            return build_error_response(
                request,
                4,
            );
        }

        /*
         * Cache
         */
        {
            let mut cache =
                self.cache.lock().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "DNS cache lock poisoned",
                    )
                })?;

            if let Some(records) =
                cache.get(
                    &domain,
                    record_type,
                )
            {
                println!("Cache hit: {}", domain);

                return build_answer(
                    request,
                    &records,
                    record_type,
                );
            }
        }

        /*
         * Root DNS
         */
        let root_result =
            match find_tld_servers(&domain) {
                Ok(result) => result,

                Err(error) => {
                    eprintln!(
                        "Root resolution failed: {}",
                        error
                    );

                    return build_error_response(
                        request,
                        2,
                    );
                }
            };

        if root_result.rcode != 0 {
            return build_error_response(
                request,
                root_result.rcode,
            );
        }

        let tld_servers =
            root_result.ip_records;

        if tld_servers.is_empty() {
            return build_error_response(
                request,
                2,
            );
        }

        /*
         * TLD DNS
         */
        let tld_result =
            match query_tld(
                &tld_servers,
                &domain,
            ) {
                Ok(result) => result,

                Err(error) => {
                    eprintln!(
                        "TLD resolution failed: {}",
                        error
                    );

                    return build_error_response(
                        request,
                        2,
                    );
                }
            };

        if tld_result.rcode != 0 {
            return build_error_response(
                request,
                tld_result.rcode,
            );
        }

        let authoritative_servers =
            tld_result.ip_records;

        if authoritative_servers.is_empty() {
            return build_error_response(
                request,
                2,
            );
        }

        /*
         * Authoritative DNS
         */
        let resolution =
            match resolve_authoritative(
                &authoritative_servers,
                &domain,
                record_type,
            ) {
                Ok(result) => result,

                Err(error) => {
                    eprintln!(
                        "Authoritative resolution failed: {}",
                        error
                    );

                    return build_error_response(
                        request,
                        2,
                    );
                }
            };

        if resolution.rcode != 0 {
            return build_error_response(
                request,
                resolution.rcode,
            );
        }

        if resolution.records.is_empty() {
            return build_error_response(
                request,
                0,
            );
        }

        /*
         * Cache the whole answer (CNAME chain included) under the
         * type that was asked for, so later lookups actually hit.
         * A chain that never reached the requested type is not cached.
         */
        if resolution
            .records
            .iter()
            .any(|record| record.record_type() == record_type)
        {
            let ttl = resolution
                .records
                .iter()
                .map(|record| record.ttl())
                .min()
                .unwrap_or(0);

            let mut cache =
                self.cache.lock().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "DNS cache lock poisoned",
                    )
                })?;

            cache.insert(
                &domain,
                record_type,
                resolution.records.clone(),
                ttl as u64,
            );

            println!(
                "Cache entries: {}",
                cache.len()
            );
        }

        build_answer(
            request,
            &resolution.records,
            record_type,
        )
    }
}

/// Build the reply from a (possibly CNAME-prefixed) record set.
fn build_answer(
    request: &[u8],
    records: &[DnsRecord],
    record_type: u16,
) -> io::Result<Vec<u8>> {
    let answer = records
        .iter()
        .find(|record| record.record_type() == record_type)
        .or_else(|| {
            records
                .iter()
                .find(|record| !matches!(record, DnsRecord::Cname(_)))
        });

    match answer {
        Some(DnsRecord::A(record))
        | Some(DnsRecord::AAAA(record)) => {
            let cname =
                records.iter().find_map(|item| match item {
                    DnsRecord::Cname(cname) => Some(cname),
                    _ => None,
                });

            let ip_record = IpRecord {
                name: record.name.clone(),
                address: record.address.clone(),
            };

            build_response_with_cname(
                request,
                cname,
                &ip_record,
            )
        }

        Some(DnsRecord::Https(record)) => {
            build_response_with_https(request, record)
        }

        _ => build_error_response(request, 0),
    }
}
