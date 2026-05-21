use core::net::SocketAddr;
use rustix::net::{AddressFamily, SocketType};

/// Represents an operation that DNS connection wants YOU to perform.
///
/// Usually the flow should be:
///
/// ```ignore
/// if let Some(op_to_exec) = conn.wants()) {
///     // run the op (do a syscall)
/// }
/// // ... later once the operation is done
/// conn.satisfy_OP_NAME(res);
/// ```
#[derive(Debug)]
pub enum DnsWants<'a> {
    /// A `socket()` opertion
    Socket {
        /// `domain` argument of the `socket()` call
        domain: AddressFamily,
        /// `type` argument of the `socket()` call
        r#type: SocketType,
        /// sequence number of a request
        seq: u64,
    },
    /// A `connect()` opertion
    Connect {
        /// `addr` argument of the `connect()` call
        addr: SocketAddr,
        /// sequence number of a request
        seq: u64,
    },
    /// A `read()` opertion
    Read {
        /// `buf` argument of the `read()` call
        buf: &'a mut [u8],
        /// sequence number of a request
        seq: u64,
    },
    /// A `write()` opertion
    Write {
        /// `buf` argument of the `write()` call
        buf: &'a [u8],
        /// sequence number of a request
        seq: u64,
    },
    /// A `close()` operation
    Close {
        /// sequence number of a request
        seq: u64,
    },
}
