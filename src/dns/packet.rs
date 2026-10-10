use std::io;

use crate::dns::query::{
    CLASS_IN,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_HTTPS,
    TYPE_OPT,
};

use crate::dns::record::{ARecord, CnameRecord, DnsRecord, HttpsRecord};

#[derive(Debug, Clone)]
pub struct NsRecord {
    pub name: String,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct IpRecord {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct EdnsInfo {
    pub udp_payload_size: u16,
    pub version: u8,
    pub flags: u16,
}

#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub records: Vec<DnsRecord>,
    pub rcode: u8,
    pub edns: Option<EdnsInfo>,
}

#[derive(Debug, Clone)]
pub struct ReferralResponse {
    pub ns_records: Vec<NsRecord>,
    pub ip_records: Vec<IpRecord>,
    pub rcode: u8,
}

fn read_u16(packet: &[u8], pos: &mut usize) -> io::Result<u16> {
    if *pos + 2 > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "u16",
        ));
    }

    let value =
        u16::from_be_bytes([packet[*pos], packet[*pos + 1]]);

    *pos += 2;

    Ok(value)
}

fn read_u32(packet: &[u8], pos: &mut usize) -> io::Result<u32> {
    if *pos + 4 > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "u32",
        ));
    }

    let value = u32::from_be_bytes([
        packet[*pos],
        packet[*pos + 1],
        packet[*pos + 2],
        packet[*pos + 3],
    ]);

    *pos += 4;

    Ok(value)
}

pub fn read_name(
    packet: &[u8],
    pos: &mut usize,
) -> io::Result<String> {
    let mut labels = Vec::new();

    let mut current = *pos;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        if current >= packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "name",
            ));
        }

        let len = packet[current];

        if len & 0xc0 == 0xc0 {
            if current + 1 >= packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "pointer",
                ));
            }

            let pointer =
                (((len as usize) & 0x3f) << 8)
                | packet[current + 1] as usize;

            if !jumped {
                *pos = current + 2;
                jumped = true;
            }

            current = pointer;

            jumps += 1;

            if jumps > 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "name loop",
                ));
            }

            continue;
        }

        if len == 0 {
            if !jumped {
                *pos = current + 1;
            }

            break;
        }

        if len & 0xc0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid label",
            ));
        }

        current += 1;

        let end = current + len as usize;

        if end > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "label",
            ));
        }

        let label =
            std::str::from_utf8(&packet[current..end])
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "label utf8",
                    )
                })?;

        labels.push(label.to_string());

        current = end;
    }

    Ok(labels.join("."))
}

pub fn parse_referral(
    packet: &[u8],
) -> io::Result<ReferralResponse> {
    if packet.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "header",
        ));
    }

    let mut pos = 0;

    let _id = read_u16(packet, &mut pos)?;
    let flags = read_u16(packet, &mut pos)?;

    let questions =
        read_u16(packet, &mut pos)? as usize;

    let answers =
        read_u16(packet, &mut pos)? as usize;

    let authority =
        read_u16(packet, &mut pos)? as usize;

    let additional =
        read_u16(packet, &mut pos)? as usize;

    let rcode = (flags & 0x000f) as u8;

    for _ in 0..questions {
        read_name(packet, &mut pos)?;
        read_u16(packet, &mut pos)?;
        read_u16(packet, &mut pos)?;
    }

    let total_records =
        answers + authority + additional;

    let mut ns_records = Vec::new();
    let mut ip_records = Vec::new();

    for _ in 0..total_records {
        let name = read_name(packet, &mut pos)?;

        let record_type =
            read_u16(packet, &mut pos)?;

        let class =
            read_u16(packet, &mut pos)?;

        let _ttl =
            read_u32(packet, &mut pos)?;

        let rdlength =
            read_u16(packet, &mut pos)? as usize;

        if pos + rdlength > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "rdata",
            ));
        }

        match record_type {
            2 if class == CLASS_IN => {
                let mut rpos = pos;

                let target =
                    read_name(packet, &mut rpos)?;

                ns_records.push(NsRecord {
                    name,
                    target,
                });
            }

            1 if class == CLASS_IN && rdlength == 4 => {
                let address = format!(
                    "{}.{}.{}.{}",
                    packet[pos],
                    packet[pos + 1],
                    packet[pos + 2],
                    packet[pos + 3]
                );

                ip_records.push(IpRecord {
                    name,
                    address,
                });
            }

            28 if class == CLASS_IN && rdlength == 16 => {
                use std::net::Ipv6Addr;

                let mut bytes = [0u8; 16];

                bytes.copy_from_slice(
                    &packet[pos..pos + 16],
                );

                let address =
                    Ipv6Addr::from(bytes).to_string();

                ip_records.push(IpRecord {
                    name,
                    address,
                });
            }

            _ => {}
        }

        pos += rdlength;
    }

    Ok(ReferralResponse {
        ns_records,
        ip_records,
        rcode,
    })
}

pub fn parse_authoritative(
    packet: &[u8],
) -> io::Result<ParsedResponse> {
    if packet.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "header",
        ));
    }

    let mut pos = 0;

    let _id = read_u16(packet, &mut pos)?;
    let flags = read_u16(packet, &mut pos)?;
    let questions = read_u16(packet, &mut pos)? as usize;
    let answers = read_u16(packet, &mut pos)? as usize;
    let authority = read_u16(packet, &mut pos)? as usize;
    let additional = read_u16(packet, &mut pos)? as usize;

    let rcode = (flags & 0x000f) as u8;

    for _ in 0..questions {
        read_name(packet, &mut pos)?;
        read_u16(packet, &mut pos)?;
        read_u16(packet, &mut pos)?;
    }

    let total_records = answers + authority + additional;
    let mut records = Vec::new();
    let mut edns = None;

    for index in 0..total_records {
        let name = read_name(packet, &mut pos)?;

        let record_type = read_u16(packet, &mut pos)?;
        let class = read_u16(packet, &mut pos)?;
        let ttl = read_u32(packet, &mut pos)?;
        let rdlength = read_u16(packet, &mut pos)? as usize;

        if pos + rdlength > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "rdata",
            ));
        }

        /*
         * EDNS OPT is a pseudo-record, not a normal DNS record.
         *
         * OPT:
         *   NAME     = root (0)
         *   TYPE     = 41
         *   CLASS    = UDP payload size
         *   TTL      = extended RCODE + version + flags
         *   RDLENGTH = option data length
         */
        if record_type == TYPE_OPT {
            if index >= answers + authority {
                let udp_payload_size = class;
                let version =
                    ((ttl >> 16) & 0xff) as u8;
                let flags =
                    (ttl & 0xffff) as u16;

                edns = Some(EdnsInfo {
                    udp_payload_size,
                    version,
                    flags,
                });
            }

            pos += rdlength;
            continue;
        }

        if index < answers && class == CLASS_IN {
            match record_type {
                TYPE_A if rdlength == 4 => {
                    let address = format!(
                        "{}.{}.{}.{}",
                        packet[pos],
                        packet[pos + 1],
                        packet[pos + 2],
                        packet[pos + 3]
                    );

                    records.push(DnsRecord::A(ARecord {
                        name,
                        address,
                        ttl,
                    }));
                }

                TYPE_AAAA if rdlength == 16 => {
                    use std::net::Ipv6Addr;

                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(
                        &packet[pos..pos + 16],
                    );

                    records.push(DnsRecord::AAAA(ARecord {
                        name,
                        address: Ipv6Addr::from(bytes).to_string(),
                        ttl,
                    }));
                }

                TYPE_CNAME => {
                    let mut rpos = pos;
                    let target = read_name(packet, &mut rpos)?;

                    records.push(DnsRecord::Cname(
                        CnameRecord {
                            name,
                            target,
                            ttl,
                        },
                    ));
                }

                TYPE_HTTPS => {
                    records.push(DnsRecord::Https(
                        HttpsRecord {
                            name,
                            ttl,
                            rdata: packet[
                                pos..pos + rdlength
                            ].to_vec(),
                        },
                    ));
                }

                _ => {}
            }
        }

        pos += rdlength;
    }

    Ok(ParsedResponse {
        records,
        rcode,
        edns,
    })
}


fn request_edns_udp_size(
    request: &[u8],
) -> io::Result<Option<u16>> {
    if request.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "request header",
        ));
    }

    let mut pos = 12;

    let questions =
        u16::from_be_bytes([
            request[4],
            request[5],
        ]) as usize;

    let additional =
        u16::from_be_bytes([
            request[10],
            request[11],
        ]) as usize;

    for _ in 0..questions {
        read_name(request, &mut pos)?;

        if pos + 4 > request.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "question",
            ));
        }

        pos += 4;
    }

    /*
     * Skip answer and authority sections.
     *
     * For the client request these are normally zero,
     * but parsing them keeps the helper structurally correct.
     */
    let answers =
        u16::from_be_bytes([
            request[6],
            request[7],
        ]) as usize;

    let authority =
        u16::from_be_bytes([
            request[8],
            request[9],
        ]) as usize;

    for _ in 0..(answers + authority) {
        read_name(request, &mut pos)?;

        if pos + 10 > request.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "resource record",
            ));
        }

        let rdlength =
            u16::from_be_bytes([
                request[pos + 8],
                request[pos + 9],
            ]) as usize;

        pos += 10;

        if pos + rdlength > request.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "rdata",
            ));
        }

        pos += rdlength;
    }

    for _ in 0..additional {
        let _name =
            read_name(request, &mut pos)?;

        if pos + 10 > request.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "OPT record",
            ));
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

        let rdlength =
            u16::from_be_bytes([
                request[pos + 8],
                request[pos + 9],
            ]) as usize;

        pos += 10;

        if pos + rdlength > request.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "OPT RDATA",
            ));
        }

        if record_type == TYPE_OPT {
            return Ok(Some(class));
        }

        pos += rdlength;
    }

    Ok(None)
}

fn append_edns_response(
    request: &[u8],
    response: &mut Vec<u8>,
) -> io::Result<()> {
    let udp_payload_size =
        match request_edns_udp_size(request)? {
            Some(size) => size,
            None => return Ok(()),
        };

    /*
     * Basic EDNS response:
     *
     * NAME     = root
     * TYPE     = OPT
     * CLASS    = UDP payload size
     * TTL      = version 0 + flags 0
     * RDLENGTH = 0
     */
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&TYPE_OPT.to_be_bytes());
    response.extend_from_slice(
        &udp_payload_size.max(512).to_be_bytes(),
    );
    response.extend_from_slice(&0u32.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    /*
     * Increase ARCOUNT by one.
     */
    if response.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response header",
        ));
    }

    let additional =
        u16::from_be_bytes([
            response[10],
            response[11],
        ]);

    let new_additional =
        additional.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "too many additional records",
            )
        })?;

    response[10..12]
        .copy_from_slice(
            &new_additional.to_be_bytes(),
        );

    Ok(())
}

pub fn build_response(
    request: &[u8],
    record: &IpRecord,
) -> io::Result<Vec<u8>> {
    build_response_with_cname(
        request,
        None,
        record,
    )
}

pub fn build_response_with_https(
    request: &[u8],
    record: &HttpsRecord,
) -> io::Result<Vec<u8>> {
    if request.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "request header",
        ));
    }

    let mut response =
        Vec::with_capacity(512);

    response.extend_from_slice(
        &request[0..2],
    );

    let request_flags =
        u16::from_be_bytes([
            request[2],
            request[3],
        ]);

    let rd =
        request_flags & 0x0100;

    let flags =
        0x8000 | 0x0080 | rd;

    response.extend_from_slice(
        &flags.to_be_bytes(),
    );

    response.extend_from_slice(
        &1u16.to_be_bytes(),
    );

    response.extend_from_slice(
        &1u16.to_be_bytes(),
    );

    response.extend_from_slice(
        &0u16.to_be_bytes(),
    );

    response.extend_from_slice(
        &0u16.to_be_bytes(),
    );

    let mut pos = 12;

    read_name(request, &mut pos)?;

    if pos + 4 > request.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "question",
        ));
    }

    response.extend_from_slice(
        &request[12..pos + 4],
    );

    /*
     * Answer owner name = original QNAME.
     */
    response.extend_from_slice(
        &0xc00cu16.to_be_bytes(),
    );

    response.extend_from_slice(
        &TYPE_HTTPS.to_be_bytes(),
    );

    response.extend_from_slice(
        &CLASS_IN.to_be_bytes(),
    );

    response.extend_from_slice(
        &record.ttl.to_be_bytes(),
    );

    let rdlength =
        u16::try_from(record.rdata.len())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTPS RDATA too large",
                )
            })?;

    response.extend_from_slice(
        &rdlength.to_be_bytes(),
    );

    response.extend_from_slice(
        &record.rdata,
    );

    append_edns_response(
        request,
        &mut response,
    )?;

    Ok(response)
}

pub fn build_response_with_cname(
    request: &[u8],
    cname: Option<&CnameRecord>,
    record: &IpRecord,
) -> io::Result<Vec<u8>> {
    if request.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "request header",
        ));
    }

    let mut response =
        Vec::with_capacity(512);

    response.extend_from_slice(
        &request[0..2],
    );

    let request_flags =
        u16::from_be_bytes([
            request[2],
            request[3],
        ]);

    let rd = request_flags & 0x0100;

    let flags =
        0x8000 | 0x0080 | rd;

    response.extend_from_slice(
        &flags.to_be_bytes(),
    );

    response.extend_from_slice(
        &1u16.to_be_bytes(),
    );

    let answer_count =
        if cname.is_some() { 2 } else { 1 };

    response.extend_from_slice(
        &(answer_count as u16).to_be_bytes(),
    );

    response.extend_from_slice(
        &0u16.to_be_bytes(),
    );

    response.extend_from_slice(
        &0u16.to_be_bytes(),
    );

    let mut pos = 12;

    read_name(request, &mut pos)?;

    if pos + 4 > request.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "question",
        ));
    }

    response.extend_from_slice(
        &request[12..pos + 4],
    );

    let mut answer_owner = 0xc00cu16;

    if let Some(cname) = cname {
        response.extend_from_slice(
            &0xc00cu16.to_be_bytes(),
        );

        response.extend_from_slice(
            &5u16.to_be_bytes(),
        );

        response.extend_from_slice(
            &CLASS_IN.to_be_bytes(),
        );

        response.extend_from_slice(
            &300u32.to_be_bytes(),
        );

        let mut encoded = Vec::new();

        for label in cname
            .target
            .trim_end_matches('.')
            .split('.')
        {
            if label.len() > 63 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CNAME label too long",
                ));
            }

            encoded.push(label.len() as u8);

            encoded.extend_from_slice(
                label.as_bytes(),
            );
        }

        encoded.push(0);

        response.extend_from_slice(
            &(encoded.len() as u16).to_be_bytes(),
        );

        // The address record is owned by the CNAME target, which
        // starts at the CNAME RDATA; point at it with a compression
        // pointer.
        if response.len() < 0x4000 {
            answer_owner =
                0xc000 | response.len() as u16;
        }

        response.extend_from_slice(
            &encoded,
        );
    }

    response.extend_from_slice(
        &answer_owner.to_be_bytes(),
    );

    let address: std::net::IpAddr =
        record.address.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IP",
            )
        })?;

    match address {
        std::net::IpAddr::V4(ip) => {
            response.extend_from_slice(
                &TYPE_A.to_be_bytes(),
            );

            response.extend_from_slice(
                &CLASS_IN.to_be_bytes(),
            );

            response.extend_from_slice(
                &300u32.to_be_bytes(),
            );

            response.extend_from_slice(
                &4u16.to_be_bytes(),
            );

            response.extend_from_slice(
                &ip.octets(),
            );
        }

        std::net::IpAddr::V6(ip) => {
            response.extend_from_slice(
                &TYPE_AAAA.to_be_bytes(),
            );

            response.extend_from_slice(
                &CLASS_IN.to_be_bytes(),
            );

            response.extend_from_slice(
                &300u32.to_be_bytes(),
            );

            response.extend_from_slice(
                &16u16.to_be_bytes(),
            );

            response.extend_from_slice(
                &ip.octets(),
            );
        }
    }

    Ok(response)
}

pub fn build_error_response(
    request: &[u8],
    rcode: u8,
) -> io::Result<Vec<u8>> {
    if request.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "request header",
        ));
    }

    let mut response =
        Vec::with_capacity(512);

    response.extend_from_slice(
        &request[0..2],
    );

    let request_flags =
        u16::from_be_bytes([
            request[2],
            request[3],
        ]);

    let rd = request_flags & 0x0100;

    let flags =
        0x8000
        | 0x0080
        | rd
        | ((rcode as u16) & 0x000f);

    response.extend_from_slice(
        &flags.to_be_bytes(),
    );

    // An unparsable question (e.g. FORMERR) is answered with an
    // empty question section instead of failing to answer at all.
    let mut pos = 12;

    let question_end = match read_name(request, &mut pos) {
        Ok(_) if pos + 4 <= request.len() => Some(pos + 4),
        _ => None,
    };

    let question_count: u16 =
        if question_end.is_some() { 1 } else { 0 };

    response.extend_from_slice(
        &question_count.to_be_bytes(),
    );

    response.extend_from_slice(
        &0u16.to_be_bytes(),
    );

    response.extend_from_slice(
        &0u16.to_be_bytes(),
    );

    response.extend_from_slice(
        &0u16.to_be_bytes(),
    );

    let Some(end) = question_end else {
        return Ok(response);
    };

    response.extend_from_slice(
        &request[12..end],
    );

    append_edns_response(
        request,
        &mut response,
    )?;

    Ok(response)
}
