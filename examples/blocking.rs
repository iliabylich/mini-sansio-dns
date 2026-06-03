use anyhow::{Context, Result};
use core::str::FromStr;
use mini_sansio_dns::{Dns, DnsRecordType, DnsWants};
use rustix::net::{AddressFamily, SocketType};
use std::net::SocketAddr;

fn main() -> Result<()> {
    let desired_record_type = {
        let arg = std::env::args()
            .nth(1)
            .context("an argument (A or AAAA) is required")?;
        DnsRecordType::from_str(&arg)?
    };

    let server_to_use: SocketAddr = "8.8.8.8:53".parse()?;
    let mut dns = Dns::new("google.com", desired_record_type)?;

    // socket
    println!("socket() started");
    let fd = rustix::net::socket(AddressFamily::INET, SocketType::DGRAM, None)?;
    println!("socket() finished");

    // connect
    println!("connect() started");
    rustix::net::connect(&fd, &server_to_use)?;
    println!("connect() finished");

    // write
    let Some(DnsWants::Write { buf, seq: _seq }) = dns.wants()? else {
        panic!("write() expected");
    };
    println!("write() started");
    let len = rustix::io::write(&fd, buf).context("write() failed")?;
    dns.satisfy_write(len).context("satisfy_write() failed")?;
    println!("write() finished");

    // read
    let Some(DnsWants::Read { buf, seq: _seq }) = dns.wants()? else {
        panic!("read() expected");
    };
    println!("read() started");
    let len = rustix::io::read(&fd, buf).context("read() failed")?;
    let (resolved, _seq) = dns.satisfy_read(len).context("satisfy_read() failed")?;
    println!("read() finished");

    println!("Resolved to {resolved:?}");

    Ok(())
}
