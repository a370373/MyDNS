use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::dns::record::DnsRecord;

const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<DnsRecord>,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct DnsCache {
    entries: HashMap<(String, u16), CacheEntry>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(
        &mut self,
        domain: &str,
        record_type: u16,
    ) -> Option<Vec<DnsRecord>> {
        let key = (
            domain.to_ascii_lowercase(),
            record_type,
        );

        let expired = match self.entries.get(&key) {
            Some(entry) => {
                Instant::now() >= entry.expires_at
            }

            None => return None,
        };

        if expired {
            self.entries.remove(&key);
            return None;
        }

        self.entries
            .get(&key)
            .map(|entry| entry.records.clone())
    }

    pub fn insert(
        &mut self,
        domain: &str,
        record_type: u16,
        records: Vec<DnsRecord>,
        ttl: u64,
    ) {
        let key = (
            domain.to_ascii_lowercase(),
            record_type,
        );

        if self.entries.len() >= MAX_ENTRIES {
            let now = Instant::now();

            self.entries
                .retain(|_, entry| entry.expires_at > now);

            if self.entries.len() >= MAX_ENTRIES {
                self.entries.clear();
            }
        }

        self.entries.insert(
            key,
            CacheEntry {
                records,
                expires_at:
                    Instant::now()
                        + Duration::from_secs(ttl),
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
