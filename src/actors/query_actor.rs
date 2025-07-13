use std::net::IpAddr;

// Import necessary modules and types
use crate::actors::messages::QueryActorMessage;

use hickory_resolver::{
    lookup_ip::LookupIp, name_server::TokioConnectionProvider, ResolveError, Resolver,
};
use tokio::sync::mpsc;
use tracing::error;

/// Resolves DNS queries by acting as an actor that processes incoming messages
pub struct QueryActor {
    // The receiver for incoming messages
    receiver: mpsc::Receiver<QueryActorMessage>,
    // The resolver used to resolve DNS queries
    resolver: Resolver<TokioConnectionProvider>,
}

impl QueryActor {
    // Constructor for the actor
    pub fn new(
        receiver: mpsc::Receiver<QueryActorMessage>,
        resolver: Resolver<TokioConnectionProvider>,
    ) -> Self {
        // Return a new actor with the given receiver and an empty key-value hash map
        Self { receiver, resolver }
    }

    // Run the actor
    pub async fn run(&mut self) {
        // Continuously receive messages and handle them
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
    }

    // Handle a message
    async fn handle_message(&self, msg: QueryActorMessage) {
        match msg {
            QueryActorMessage::Resolve { name, respond_to } => {
                let lookup_result: Result<LookupIp, ResolveError> =
                    self.resolver.lookup_ip(&name).await;
                match lookup_result {
                    Ok(lookup) => {
                        // Collect all IP addresses (both IPv4 and IPv6) from the lookup.
                        // When you call resolver.lookup_ip(&name), the returned LookupIp type is not a simple collection of data.
                        // It's an iterator that is tied to the lifetime of the resolver and the name it was called with.
                        // We need to collect the IP addresses into a Vec<IpAddr>.
                        let ips: Vec<IpAddr> = lookup.iter().collect();

                        if !ips.is_empty() {
                            let _ = respond_to.send(Some(ips));
                        } else {
                            // If the lookup was successful but returned no IPs
                            let _ = respond_to.send(None);
                        }
                    }
                    Err(e) => {
                        error!("DNS lookup failed for {}: {}", name, e);
                        let _ = respond_to.send(None);
                    }
                }
            }
        }
    }
}
