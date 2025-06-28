use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(name = "rust-dns")]
#[command(about = "A DNS server written in Rust", long_about = None)]
pub struct Args {
    /// Resolver, where <address> will be of the form <ip>:<port>
    #[arg(short, long, value_parser = parse_socket_addr)]
    pub resolver: Option<SocketAddr>,
}

fn parse_socket_addr(s: &str) -> Result<SocketAddr, String> {
    s.parse::<SocketAddr>().map_err(|_| {
        format!(
            "Invalid address format: '{}'. Expected format: <ip>:<port>",
            s
        )
    })
}

impl Args {
    pub fn parse_args() -> Self {
        Self::parse()
    }
    pub fn resolver(&self) -> Option<SocketAddr> {
        self.resolver
    }
}
