// #![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::type_complexity)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_qualifications)]
#![warn(deprecated_in_future)]
#![warn(unused_lifetimes)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::arithmetic_side_effects)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![doc = include_str!("../README.md")]

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const MAX_DNS_PACKET_LEN: usize = 512;

mod error;
pub use error::DnsError;

mod name;
mod request;
mod response;

mod wants;
pub use wants::DnsWants;

mod sansio;
pub use sansio::Dns;

mod record_type;
pub use record_type::DnsRecordType;
