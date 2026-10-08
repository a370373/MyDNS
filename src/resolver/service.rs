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
                if let Some(record) =
                    records.first()
                {
                    match record {
                        DnsRecord::A(record)
                        | DnsRecord::AAAA(record) => {
                            println!(
                                "Cache hit: {}",
                                record.address
                            );

                            let ip_record =
                                IpRecord {
                                    name: record.name.clone(),
                                    address: record.address.clone(),
                                };

                            return build_response_with_cname(
                                request,
                                None,
                                &ip_record,
                            );
                        }

                        DnsRecord::Https(record) => {
                            println!(
                                "Cache hit HTTPS: {}",
                                record.name
                            );

                            return build_response_with_https(
                                request,
                                record,
                            );
                        }

                        DnsRecord::Cname(_) => {}
                    }
                }
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

        let record =
            &resolution.records[0];

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

            cache.insert(
                &domain,
                record.record_type(),
                vec![record.clone()],
                record.ttl() as u64,
            );

            println!(
                "Cache entries: {}",
                cache.len()
            );
        }

        println!(
            "Answer: {} {}",
            record.name(),
            record.record_type()
        );

        /*
         * Build response
         */
        match record {
            DnsRecord::A(record)
            | DnsRecord::AAAA(record) => {
                let ip_record =
                    IpRecord {
                        name: record.name.clone(),
                        address: record.address.clone(),
                    };

                let cname =
                    resolution.records.iter().find_map(
                        |item| {
                            match item {
                                DnsRecord::Cname(cname) => {
                                    Some(cname)
                                }

                                _ => None,
                            }
                        },
                    );

                build_response_with_cname(
                    request,
                    cname,
                    &ip_record,
                )
            }

            DnsRecord::Https(record) => {
                build_response_with_https(
                    request,
                    record,
                )
            }

            DnsRecord::Cname(_) => {
                build_error_response(
                    request,
                    0,
                )
            }
        }
    }
}
