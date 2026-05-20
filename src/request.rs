use crate::{CLASS_IN, MAX_DNS_PACKET_LEN, error::DnsError};

pub struct Request;

impl Request {
    pub(crate) fn write(
        buf: &mut [u8; MAX_DNS_PACKET_LEN],
        domain: &[u8],
        qtype: u16,
    ) -> Result<usize, DnsError> {
        let mut len = 0;

        // https://datatracker.ietf.org/doc/html/rfc1035

        // ID
        Self::write_u16(buf, &mut len, 0xABCD)?;

        // QR + Opcode + AA + TC + RD + RA + Z + RCODE
        // Query + Recursion Desired
        Self::write_u16(buf, &mut len, 0x0100)?;

        // QDCOUNT
        Self::write_u16(buf, &mut len, 1)?;

        // ANCOUNT
        Self::write_u16(buf, &mut len, 0)?;

        // NSCOUNT
        Self::write_u16(buf, &mut len, 0)?;

        // ARCOUNT
        Self::write_u16(buf, &mut len, 0)?;

        // QNAME
        for label in domain.split(|byte| *byte == b'.') {
            if label.len() > 63 {
                return Err(DnsError::DnsNameIsTooLong);
            }
            Self::write_u8(
                buf,
                &mut len,
                u8::try_from(label.len()).map_err(|_| DnsError::DnsNameIsTooLong)?,
            )?;
            for byte in label {
                Self::write_u8(buf, &mut len, *byte)?;
            }
        }
        Self::write_u8(buf, &mut len, 0)?;

        // QTYPE
        Self::write_u16(buf, &mut len, qtype)?;

        // QCLASS
        Self::write_u16(buf, &mut len, CLASS_IN)?;

        Ok(len)
    }

    fn write_u8(
        buf: &mut [u8; MAX_DNS_PACKET_LEN],
        len: &mut usize,
        byte: u8,
    ) -> Result<(), DnsError> {
        *buf.get_mut(*len).ok_or(DnsError::DnsNameIsTooLong)? = byte;
        buf[*len] = byte;
        *len = len.checked_add(1).ok_or(DnsError::DnsNameIsTooLong)?;
        Ok(())
    }

    fn write_u16(
        buf: &mut [u8; MAX_DNS_PACKET_LEN],
        len: &mut usize,
        dbyte: u16,
    ) -> Result<(), DnsError> {
        let bytes = dbyte.to_be_bytes();
        buf.get_mut(*len..len.checked_add(2).ok_or(DnsError::DnsNameIsTooLong)?)
            .ok_or(DnsError::DnsNameIsTooLong)?
            .copy_from_slice(&bytes);
        *len = len.checked_add(2).ok_or(DnsError::DnsNameIsTooLong)?;
        Ok(())
    }
}
