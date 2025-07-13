use std::net::IpAddr;

use tokio::sync::oneshot;

/// The ActorMessage enum defines the kind of messages we can send to the actor.
/// By using an enum, we can have many different message types,
/// and each message type can have its own set of arguments.
/// We return a value to the sender by using an oneshot channel,
/// which is a message passing channel that allows sending exactly one message.
#[derive(Debug)]
pub enum QueryActorMessage {
    /// Resolve a DNS name to an IPv4 address.
    Resolve {
        name: String,
        respond_to: oneshot::Sender<Option<Vec<IpAddr>>>,
    },
}
