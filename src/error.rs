/// DNS error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// DNS name is too long (either as a whole or one of its '.'-separated components)
    DnsNameIsTooLong,

    /// Invalid DNS response
    InvalidDnsResponse,

    /// Truncated DNS packet received
    TruncatedPacket,

    /// Truncated DNS label received
    TruncatedLabel,

    /// Truncated DNS name received
    TruncatedName,

    /// Truncated compression pointer received,
    TruncatedCompressionPointer,

    /// Truncated RDATA Resource Record (RR)
    TruncatedRdata,

    /// Bad compression pointer received
    BadCompressionPointer,

    /// No reply found in DNS response
    NoReplyFoundInResponse,

    /// Internal error
    InternalError(String),

    /// Unknown DNS record type
    UnknownDnsRecordType(String),
}

impl core::fmt::Display for DnsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for DnsError {}
