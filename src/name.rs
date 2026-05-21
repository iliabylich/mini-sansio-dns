use crate::DnsError;

pub struct DnsName {
    buf: [u8; 253],
    len: usize,
}

impl DnsName {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0u8; 253],
            len: 0,
        }
    }

    pub(crate) fn push_label(&mut self, label: &[u8]) -> Result<(), DnsError> {
        if self.len > 0 {
            self.push_u8(b'.')?;
        }
        for byte in label {
            self.push_u8(*byte)?;
        }
        Ok(())
    }

    fn push_u8(&mut self, byte: u8) -> Result<(), DnsError> {
        *self.buf.get_mut(self.len).ok_or(DnsError::InternalError)? = byte;
        self.len = self.len.checked_add(1).ok_or(DnsError::InternalError)?;
        Ok(())
    }

    pub(crate) fn as_bytes(&self) -> Result<&[u8], DnsError> {
        self.buf.get(..self.len).ok_or(DnsError::InternalError)
    }
}

impl core::fmt::Debug for DnsName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DNS({:?})",
            core::str::from_utf8(self.as_bytes().unwrap_or(b"<malformed>"))
        )
    }
}
