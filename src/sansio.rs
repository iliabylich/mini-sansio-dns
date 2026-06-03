use crate::{
    DnsError, DnsRecordType, DnsWants, MAX_DNS_PACKET_LEN, request::Request, response::Response,
};
use core::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Write,
    Read,
    Done,
}

/// Sans-IO implementation of DNS
#[must_use]
pub struct Dns {
    state: State,
    seq: u64,
    buf: [u8; MAX_DNS_PACKET_LEN],
    len: usize,
    pos: usize,
    desired_record_type: DnsRecordType,
}

impl Dns {
    /// Constructs a new DNS resolver
    ///
    /// # Errors
    ///
    /// Returns an error if given domain is too long
    pub fn new(domain: &str, desired_record_type: DnsRecordType) -> Result<Self, DnsError> {
        let mut buf = [0_u8; MAX_DNS_PACKET_LEN];
        let len = Request::write(&mut buf, domain.as_bytes(), desired_record_type.into_raw())?;

        Ok(Self {
            state: State::Write,
            seq: 0,
            buf,
            len,
            pos: 0,
            desired_record_type,
        })
    }

    /// Returns what DNS resolver currently wants.
    ///
    /// It's a responsibility of the caller to do a syscall and pass
    /// its result to `satisfy_X` function.
    ///
    /// # Errors
    ///
    /// Returns an error if there's an internal state error.
    pub fn wants(&mut self) -> Result<Option<DnsWants<'_>>, DnsError> {
        match self.state {
            State::Write => {
                let buf = self
                    .buf
                    .get(self.pos..self.len)
                    .ok_or(DnsError::InternalError)?;
                Ok(Some(DnsWants::Write { buf, seq: self.seq }))
            }

            State::Read => {
                let buf = self
                    .buf
                    .get_mut(self.len..)
                    .ok_or(DnsError::InternalError)?;
                Ok(Some(DnsWants::Read { buf, seq: self.seq }))
            }

            State::Done => Ok(None),
        }
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
            return Err(DnsError::InternalError);
        }

        self.pos = self
            .pos
            .checked_add(bytes_written)
            .ok_or(DnsError::InvalidDnsResponse)?;
        self.increment_seq()?;

        if self.pos > self.len {
            return Err(DnsError::InternalError);
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
    pub fn satisfy_read(&mut self, bytes_read: usize) -> Result<(SocketAddr, u64), DnsError> {
        if self.state != State::Read {
            return Err(DnsError::InternalError);
        }

        self.len = self
            .len
            .checked_add(bytes_read)
            .ok_or(DnsError::InvalidDnsResponse)?;
        self.increment_seq()?;

        if self.len > MAX_DNS_PACKET_LEN {
            return Err(DnsError::InternalError);
        }

        self.state = State::Done;

        let buf = self
            .buf
            .get(..self.len)
            .ok_or(DnsError::InvalidDnsResponse)?;
        let addr = Response::read(buf, self.desired_record_type)?;
        Ok((addr, self.seq))
    }

    fn increment_seq(&mut self) -> Result<(), DnsError> {
        self.seq = self.seq.checked_add(1).ok_or(DnsError::InternalError)?;
        Ok(())
    }
}
