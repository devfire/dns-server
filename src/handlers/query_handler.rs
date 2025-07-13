use std::net::IpAddr;

use hickory_resolver::Resolver;
use tokio::sync::{mpsc, oneshot};
// pub mod actors;

use hickory_resolver::name_server::TokioConnectionProvider;

use crate::actors::{messages::QueryActorMessage, query_actor::QueryActor};

#[derive(Clone, Debug)]
pub struct QueryActorHandle {
    sender: mpsc::Sender<QueryActorMessage>,
}

// Gives you access to the underlying actor.
impl QueryActorHandle {
    pub fn new(resolver: Resolver<TokioConnectionProvider>) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let mut actor = QueryActor::new(receiver, resolver);
        tokio::spawn(async move { actor.run().await });

        Self { sender }
    }

    /// Resolves a DNS name to an IPv4 address.
    pub async fn resolve(&self, name: String) -> Option<Vec<IpAddr>> {
        let (send, recv) = oneshot::channel();
        let msg = QueryActorMessage::Resolve {
            name,
            respond_to: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.sender.send(msg).await;

        // this is going back once the msg comes back from the actor.
        // NOTE: we might get None back, i.e. no value for the given key.
        if let Some(ips) = recv.await.expect("Actor task has been killed") {
            Some(ips)
        } else {
            None
        }
    }
}
