use anyhow::{Context, Result, bail};
use core::str::FromStr;
use mini_sansio_dns::{Dns, DnsRecordType, DnsWants};

fn main() -> Result<()> {
    env_logger::init();

    let desired_record_type = {
        let arg = std::env::args()
            .nth(1)
            .context("an argument (A or AAAA) is required")?;
        DnsRecordType::from_str(&arg)?
    };

    let mut dns = Dns::new("google.com", "8.8.8.8:53".parse()?, desired_record_type);

    let DnsWants::Socket {
        domain,
        r#type,
        seq: _seq,
    } = dns.wants()
    else {
        bail!("socket() expected");
    };
    log::info!("socket() started");
    let fd = rustix::net::socket(domain, r#type, None).context("socket() failed")?;
    dns.satisfy_socket().context("satisfy_socket() failed")?;
    log::info!("socket() finished");

    let DnsWants::Connect { addr, seq: _seq } = dns.wants() else {
        panic!("connect() expected");
    };
    log::info!("connect() started");
    rustix::net::connect(&fd, &addr).context("connect() failed")?;
    dns.satisfy_connect().context("satisfy_connect() failed")?;
    log::info!("connect() finished");

    let DnsWants::Write { buf, seq: _seq } = dns.wants() else {
        panic!("write() expected");
    };
    log::info!("write() started");
    let len = rustix::io::write(&fd, buf).context("write() failed")?;
    dns.satisfy_write(len).context("satisfy_write() failed")?;
    log::info!("write() finished");

    let DnsWants::Read { buf, seq: _seq } = dns.wants() else {
        panic!("read() expected");
    };
    log::info!("read() started");
    let len = rustix::io::read(&fd, buf).context("read() failed")?;
    dns.satisfy_read(len).context("satisfy_read() failed")?;
    log::info!("read() finished");

    let DnsWants::Close { seq: _seq } = dns.wants() else {
        panic!("close() expected");
    };
    log::info!("close() started");
    drop(fd);
    let (resolved, _seq) = dns.satisfy_close().context("satisfy_close() failed")?;
    log::info!("close() finished");

    log::info!("Resolved to {resolved:?}");

    Ok(())
}
