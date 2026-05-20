use crate::{DnsError, TYPE_A, TYPE_AAAA};
use std::str::FromStr;

/// DNS record type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    /// A (IPv4)
    A,
    /// AAAA (IPv6)
    AAAA,
}

impl DnsRecordType {
    pub(crate) const fn into_raw(self) -> u16 {
        match self {
            Self::A => TYPE_A,
            Self::AAAA => TYPE_AAAA,
        }
    }
}

impl FromStr for DnsRecordType {
    type Err = DnsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            _ => Err(DnsError::UnknownDnsRecordType(s.to_string())),
        }
    }
}
