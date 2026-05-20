use crate::{
    DnsError, DnsRecordType, DnsWants, MAX_DNS_PACKET_LEN, request::Request, response::Response,
};
use rustix::net::{AddressFamily, SocketType};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Socket,
    Connect,
    Write,
    Read,
    Close,
}

/// Sans-IO implementation of DNS
#[must_use]
pub struct Dns<'a> {
    state: State,
    seq: u64,
    server_to_use: SocketAddr,
    buf: [u8; MAX_DNS_PACKET_LEN],
    len: usize,
    pos: usize,
    domain: &'a str,
    desired_record_type: DnsRecordType,
}

impl<'a> Dns<'a> {
    /// Constructs a new DNS resolver
    pub const fn new(
        domain: &'a str,
        server_to_use: SocketAddr,
        desired_record_type: DnsRecordType,
    ) -> Self {
        Self {
            state: State::Socket,
            seq: 0,
            server_to_use,
            buf: [0; _],
            len: 0,
            pos: 0,
            domain,
            desired_record_type,
        }
    }

    /// Returns what DNS resolver currently wants.
    ///
    /// It's a responsibility of the caller to do a syscall and pass
    /// its result to `satisfy_X` function.
    pub fn wants(&mut self) -> DnsWants<'_> {
        match self.state {
            State::Socket => DnsWants::Socket {
                domain: if self.server_to_use.is_ipv4() {
                    AddressFamily::INET
                } else {
                    AddressFamily::INET6
                },
                r#type: SocketType::DGRAM,
                seq: self.seq,
            },

            State::Connect => DnsWants::Connect {
                addr: self.server_to_use,
                seq: self.seq,
            },

            State::Write => {
                // SAFETY: len never exceeds buf's size
                let buf = unsafe { self.buf.get_unchecked(self.pos..self.len) };
                DnsWants::Write { buf, seq: self.seq }
            }

            State::Read => {
                // SAFETY: len never exceeds buf's size
                let buf = unsafe { self.buf.get_unchecked_mut(self.len..) };
                DnsWants::Read { buf, seq: self.seq }
            }

            State::Close => DnsWants::Close { seq: self.seq },
        }
    }

    /// Satisfies `socket()` operation.
    ///
    /// It's a responsility of the caller to validate result of the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `socket()` wasn't the last operation returned from `wants()`
    pub fn satisfy_socket(&mut self) -> Result<(), DnsError> {
        if self.state != State::Socket {
            return Err(DnsError::InternalError(format!(
                "malformed state, expected Socket, got {:?}",
                self.state,
            )));
        }

        self.state = State::Connect;
        self.increment_seq()?;
        Ok(())
    }

    /// Satisfies `connect()` operation.
    ///
    /// It's a responsility of the caller to validate result of the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `connect()` wasn't the last operation returned from `wants()`
    pub fn satisfy_connect(&mut self) -> Result<(), DnsError> {
        if self.state != State::Connect {
            return Err(DnsError::InternalError(format!(
                "malformed state, expected Connect, got {:?}",
                self.state,
            )));
        }

        let mut buf = [0_u8; MAX_DNS_PACKET_LEN];
        let len = Request::write(
            &mut buf,
            self.domain.as_bytes(),
            self.desired_record_type.into_raw(),
        )?;

        self.state = State::Write;
        self.increment_seq()?;

        self.buf = buf;
        self.len = len;
        self.pos = 0;
        Ok(())
    }

    /// Satisfies `write()` operation.
    ///
    /// It's a responsility of the caller to validate result of the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `write()` wasn't the last operation returned from `wants()`
    pub fn satisfy_write(&mut self, bytes_written: usize) -> Result<(), DnsError> {
        if self.state != State::Write {
            return Err(DnsError::InternalError(format!(
                "malformed state, expected Write, got {:?}",
                self.state,
            )));
        }

        self.pos = self
            .pos
            .checked_add(bytes_written)
            .ok_or(DnsError::InvalidDnsResponse)?;
        self.increment_seq()?;

        if self.pos > self.len {
            return Err(DnsError::InternalError(format!(
                "malformed state, pos > len: {} > {}",
                self.pos, self.len
            )));
        }

        if self.pos == self.len {
            self.state = State::Read;
            self.buf = [0; _];
            self.len = 0;
        }
        Ok(())
    }

    /// Satisfies `read()` operation.
    ///
    /// It's a responsility of the caller to validate result of the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `read()` wasn't the last operation returned from `wants()`
    /// OR if too many bytes have been read from the net socket.
    pub fn satisfy_read(&mut self, bytes_read: usize) -> Result<(), DnsError> {
        if self.state != State::Read {
            return Err(DnsError::InternalError(format!(
                "malformed state, expected Read, got {:?}",
                self.state,
            )));
        }

        self.len = self
            .len
            .checked_add(bytes_read)
            .ok_or(DnsError::InvalidDnsResponse)?;
        self.increment_seq()?;

        if self.len > MAX_DNS_PACKET_LEN {
            return Err(DnsError::InternalError(format!(
                "malformed state, len > MAX_DNS_PACKET_LEN: {} > {MAX_DNS_PACKET_LEN}",
                self.len
            )));
        }

        self.state = State::Close;
        Ok(())
    }

    /// Satisfies `close()` operation and returns captured `SocketAddr` that's been received from the DNS server.
    ///
    /// It's a responsility of the caller to validate result of the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `connect()` wasn't the last operation returned from `wants()`
    /// OR if bytes returned from the DNS server represent an invalid DNS packet.
    pub fn satisfy_close(&mut self) -> Result<(SocketAddr, u64), DnsError> {
        if self.state != State::Close {
            return Err(DnsError::InternalError(format!(
                "malformed state, expected Close, got {:?}",
                self.state,
            )));
        }

        self.increment_seq()?;

        let buf = self
            .buf
            .get(..self.len)
            .ok_or(DnsError::InvalidDnsResponse)?;
        let addr = Response::read(buf, self.desired_record_type)?;
        Ok((addr, self.seq))
    }

    fn increment_seq(&mut self) -> Result<(), DnsError> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(DnsError::InvalidDnsResponse)?;
        Ok(())
    }
}
