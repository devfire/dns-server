mod cli;
mod codec;
mod errors;
mod parsers;
mod processor;
mod protocol;
mod response_builder;

mod actors;
mod handlers;

use crate::handlers::query_handler::QueryActorHandle;
use crate::processor::process_dns_query;

use std::net::{Ipv4Addr, SocketAddr};


use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::xfer::Protocol,
    Resolver,
};

use tokio::net::UdpSocket;


use tracing::{info, Level};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    let args = cli::Args::parse_args();

    use std::sync::Arc;
    let sock = Arc::new(UdpSocket::bind("0.0.0.0:2053").await?);

    let resolver_ip_port = args.resolver().unwrap_or(SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        53,
    )); // Default to Google's public DNS

    // Create a new resolver configuration.
    let mut resolver_config = ResolverConfig::new();
    let name_server_config = NameServerConfig {
        socket_addr: resolver_ip_port,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        http_endpoint: None,
        trust_negative_responses: true,
        bind_addr: None,
    };

    resolver_config.add_name_server(name_server_config);

    // Create a new resolver instance with the configuration.
    let resolver =
        Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default()).build();

    // Create a new actor handle for the query actor.
    let query_actor_handle = QueryActorHandle::new(resolver.clone());

    let mut buf = [0; 1024]; // Buffer for incoming packets

    info!("DNS server listening on 0.0.0.0:2053");

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;

        let packet_data = buf[..len].to_vec();
        let sock_clone = Arc::clone(&sock); // Arc<UdpSocket>
        let query_handle = query_actor_handle.clone(); // Clone the actor handle
                                                       // let sock_clone = sock.clone(); // Arc<UdpSocket>

        // Spawn a new task to process the DNS query
        tokio::spawn(async move {
            process_dns_query(packet_data, addr, query_handle, sock_clone).await;
        });
    }
}
