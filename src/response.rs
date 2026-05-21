use crate::{CLASS_IN, DnsError, DnsRecordType, TYPE_A, TYPE_AAAA, name::DnsName};
use core::net::SocketAddr;

pub struct Response;

impl Response {
    pub(crate) fn read(
        buf: &[u8],
        desired_record_type: DnsRecordType,
    ) -> Result<SocketAddr, DnsError> {
        let mut pos = 0;

        let _id = read_u16(buf, &mut pos)?;
        let flags = read_u16(buf, &mut pos)?;
        let qdcount = read_u16(buf, &mut pos)?;
        let ancount = read_u16(buf, &mut pos)?;
        let _nscount = read_u16(buf, &mut pos)?;
        let _arcount = read_u16(buf, &mut pos)?;

        if flags & 0x8000 == 0 || flags & 0x0200 != 0 || flags & 0x000F != 0 {
            return Err(DnsError::InvalidDnsResponse);
        }

        for _ in 0..qdcount {
            let _ = read_name(buf, &mut pos)?;
            let _ = read_bytes::<4>(buf, &mut pos)?;
        }

        for _ in 0..ancount {
            let _name = read_name(buf, &mut pos)?;
            let rtype = read_u16(buf, &mut pos)?;
            let rclass = read_u16(buf, &mut pos)?;
            let _ttl = read_u32(buf, &mut pos)?;
            let rdlength = read_u16(buf, &mut pos)?;

            if rclass != CLASS_IN || rtype != desired_record_type.into_raw() {
                let _ignore = read_slice(buf, &mut pos, rdlength as usize)?;
                continue;
            }

            if rtype == TYPE_A && rdlength == 4 {
                return Ok(SocketAddr::from((read_bytes::<4>(buf, &mut pos)?, 0)));
            }

            if rtype == TYPE_AAAA && rdlength == 16 {
                return Ok(SocketAddr::from((read_bytes::<16>(buf, &mut pos)?, 0)));
            }

            let _ = read_slice(buf, &mut pos, rdlength as usize)?;
        }

        Err(DnsError::NoReplyFoundInResponse)
    }
}

fn read_bytes<const N: usize>(buf: &[u8], pos: &mut usize) -> Result<[u8; N], DnsError> {
    let start = *pos;
    let end = start.checked_add(N).ok_or(DnsError::InternalError)?;

    let bytes = buf.get(start..end).ok_or(DnsError::TruncatedPacket)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    *pos = end;
    Ok(out)
}

fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16, DnsError> {
    Ok(u16::from_be_bytes(read_bytes(buf, pos)?))
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, DnsError> {
    Ok(u32::from_be_bytes(read_bytes(buf, pos)?))
}

fn read_name(buf: &[u8], pos: &mut usize) -> Result<DnsName, DnsError> {
    let mut name = DnsName::new();
    let mut cursor = *pos;
    let mut jumped = false;
    let mut jumps = 0_u8;

    loop {
        let byte = *buf.get(cursor).ok_or(DnsError::TruncatedName)?;

        if byte == 0 {
            if !jumped {
                *pos = cursor.checked_add(1).ok_or(DnsError::InvalidDnsResponse)?;
            }
            return Ok(name);
        }

        if byte & 0xC0 == 0xC0 {
            let low = *buf
                .get(cursor.checked_add(1).ok_or(DnsError::InvalidDnsResponse)?)
                .ok_or(DnsError::TruncatedCompressionPointer)?;

            if !jumped {
                *pos = cursor.checked_add(2).ok_or(DnsError::InvalidDnsResponse)?;
            }

            cursor = ((byte & 0x3F) as usize) << 8 | low as usize;
            jumped = true;
            jumps = jumps
                .checked_add(1)
                .ok_or(DnsError::BadCompressionPointer)?;

            if jumps > 16 {
                return Err(DnsError::BadCompressionPointer);
            }

            continue;
        }

        if byte & 0xC0 != 0 {
            return Err(DnsError::InvalidDnsResponse);
        }

        let len = byte as usize;
        let start = cursor.checked_add(1).ok_or(DnsError::InvalidDnsResponse)?;
        let end = start.checked_add(len).ok_or(DnsError::InvalidDnsResponse)?;
        let label = buf.get(start..end).ok_or(DnsError::TruncatedLabel)?;

        name.push_label(label)?;
        cursor = end;

        if !jumped {
            *pos = cursor;
        }
    }
}

fn read_slice<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], DnsError> {
    let start = *pos;
    let end = start.checked_add(len).ok_or(DnsError::InvalidDnsResponse)?;
    let out = buf.get(start..end).ok_or(DnsError::TruncatedRdata)?;
    *pos = end;
    Ok(out)
}
