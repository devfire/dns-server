/// Errors that can occur during DNS packet codec operations
#[derive(Debug, thiserror::Error)]
pub enum DnsCodecError {
    // #[error("Parsing error: {0}")]
    // ParseError(String),

    #[error("Incomplete packet: need at least {needed} bytes, have {available}")]
    IncompletePacket { needed: usize, available: usize },

    // #[error("Invalid packet format: {0}")]
    // InvalidFormat(String),

    #[error("Nom parsing error: {0}")]
    NomError(String),

    #[error("Invalid domain name: {0}")]
    InvalidDomainName(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
