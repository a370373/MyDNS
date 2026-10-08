#[derive(Debug, Clone)]
pub struct ARecord {
    pub name: String,
    pub address: String,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
pub struct CnameRecord {
    pub name: String,
    pub target: String,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
pub struct HttpsRecord {
    pub name: String,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DnsRecord {
    A(ARecord),
    AAAA(ARecord),
    Cname(CnameRecord),
    Https(HttpsRecord),
}

impl DnsRecord {
    pub fn name(&self) -> &str {
        match self {
            Self::A(record) => &record.name,
            Self::AAAA(record) => &record.name,
            Self::Cname(record) => &record.name,
            Self::Https(record) => &record.name,
        }
    }

    pub fn ttl(&self) -> u32 {
        match self {
            Self::A(record) => record.ttl,
            Self::AAAA(record) => record.ttl,
            Self::Cname(record) => record.ttl,
            Self::Https(record) => record.ttl,
        }
    }

    pub fn record_type(&self) -> u16 {
        match self {
            Self::A(_) => 1,
            Self::AAAA(_) => 28,
            Self::Cname(_) => 5,
            Self::Https(_) => 65,
        }
    }
}
