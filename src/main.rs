mod cli;
mod codec;
mod errors;
mod parsers;
mod protocol;
mod response_builder;

mod actors;
mod handlers;

use crate::handlers::query_handler::QueryActorHandle;

use std::net::{Ipv4Addr, SocketAddr};

use bytes::BytesMut;
use codec::DnsCodec;
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::xfer::Protocol,
    Resolver,
};
use response_builder::DnsResponseBuilder;
use tokio::net::UdpSocket;
use tokio_util::codec::{Decoder, Encoder};

use tracing::{debug, error, info, Level};

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

    let sock = UdpSocket::bind("0.0.0.0:2053").await?;

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

    // Create a new DNS codec instance.
    let mut codec = DnsCodec::new();
    let mut buf = [0; 1024];

    info!("DNS server listening on 0.0.0.0:2053");

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        debug!("Received {} bytes from {}", len, addr);

        // Create a BytesMut from the received data
        let mut bytes_mut = BytesMut::from(&buf[..len]);

        // Use the codec to decode the DNS packet
        match codec.decode(&mut bytes_mut) {
            Ok(Some(packet)) => {
                debug!(
                    "Successfully decoded DNS packet from {}: {:?}",
                    addr, packet.header
                );

                debug!(
                    target: "dns_server::packet_details",
                    packet_id = packet.header.id,
                    query_response = if packet.header.qr { "Response" } else { "Query" },
                    opcode = packet.header.opcode, // This can be mapped to a string if needed
                    // opcode = match packet.header.opcode {
                    //     0 => "QUERY",
                    //     1 => "IQUERY",
                    //     2 => "STATUS",
                    //     _ => "RESERVED"
                    // },
                    authoritative = packet.header.aa,
                    truncated = packet.header.tc,
                    recursion_desired = packet.header.rd,
                    recursion_available = packet.header.ra,
                    response_code = match packet.header.rcode {
                        0 => "NOERROR",
                        1 => "FORMERR",
                        2 => "SERVFAIL",
                        3 => "NXDOMAIN",
                        4 => "NOTIMP",
                        5 => "REFUSED",
                        _ => "UNKNOWN"
                    },
                    question_count = packet.header.qdcount,
                    answer_count = packet.header.ancount,
                    authority_count = packet.header.nscount,
                    additional_count = packet.header.arcount,
                    "DNS packet header parsed successfully"
                );

                // Create a DNS response packet
                // let response_packet = create_dns_response(packet);

                // Alternative using builder pattern (more flexible):
                // let response_packet = response_builder.build_response(&packet);
                //
                // Or with custom settings and domain:
                /*
                NOTE: When using the fluent interface with ResponseBuilder,
                we need to call at least one with_*_record() method (like with_a_record(), with_aaaa_record(), etc.) to add questions,
                otherwise the builder falls back to using the original query's questions
                 */
                // let mut response_builder = DnsResponseBuilder::new().build_custom_response(&packet);

                // Create a new builder for each request (thread-safe)
                let mut dns_response_builder = DnsResponseBuilder::new();

                let response_builder_fluent = dns_response_builder
                    .build_custom_response(&packet)
                    // leave Packet Identifier (ID) intact
                    .with_qr(true) // Set QR bit to true for response
                    // Leave Opcode as is (same as request)
                    .with_authoritative(false) // Set AA bit to false (not authoritative)
                    // Leave TC bit as is (not truncated)
                    // Leave RD bit as is (recursion desired)
                    .with_recursion_available(false)
                    // Set RA bit to false (recursion not available)
                    .with_z(0); // Reserved bits set to 0
                                // .with_rcode(0) // NOERROR
                                // NOTE: rcode is 0 (no error) if OPCODE is 0 (standard query) else 4 (not implemented)
                                // .with_an_answer("", Ipv4Addr::new(1, 1, 1, 1), 3600)
                                // .build();

                // Iterate over the questions in the original packet
                // and add them to the response packet
                // debug!("Processing {} questions", packet.questions.len());
                let mut response_builder_chain = response_builder_fluent;

                for question in packet.questions.iter() {
                    // `resolve` now returns an Option<Vec<IpAddr>>
                    if let Some(ip_addrs) = query_actor_handle.resolve(question.name.clone()).await
                    {
                        if ip_addrs.is_empty() {
                            error!("Could not resolve {}: No IPs found", &question.name);
                        } else {
                            // Iterate over all returned IP addresses and add them to the response
                            for ip_addr in ip_addrs {
                                info!("Resolved {} -> {}", &question.name, ip_addr);
                                response_builder_chain = response_builder_chain.with_an_answer(
                                    &question.name,
                                    ip_addr, // This is already an IpAddr
                                    60,
                                );
                            }
                        }
                    } else {
                        error!("Could not resolve {}: Lookup failed", &question.name);
                        // Optionally, set the RCODE to NXDOMAIN or similar
                    }
                }

                let response_packet = response_builder_chain.build();
                // Other examples (commented out):
                // Direct domain response: response_builder.build_domain_response("example.com", packet.header.id);
                // Multiple domains: response_builder.build_multi_domain_response(&["google.com", "github.com"], packet.header.id);
                // Different record types: .with_aaaa_record("ipv6.google.com"), .with_cname_record("www.example.com"), etc.

                // Encode the response packet
                let mut response_buf = BytesMut::new();
                match codec.encode(response_packet, &mut response_buf) {
                    Ok(()) => {
                        let response_len = sock.send_to(&response_buf, addr).await?;
                        info!("Sent DNS response ({} bytes) to {}", response_len, addr);
                    }
                    Err(e) => {
                        error!("Failed to encode DNS response for {}: {}", addr, e);
                        // Fallback to echoing original data
                        let response_len = sock.send_to(&buf[..len], addr).await?;
                        info!("Fallback: echoed {} bytes back to {}", response_len, addr);
                    }
                }
            }
            Ok(None) => {
                info!("Incomplete packet received from {}, ignoring", addr);
            }
            Err(e) => {
                error!("Failed to decode DNS packet from {}: {}", addr, e);
                // Continue processing other packets even if one fails
            }
        }
    }
}
