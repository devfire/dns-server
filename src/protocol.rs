// Define DNS packet structure and parsing logic

#[derive(Debug, Clone, Copy)]
pub struct DnsPacketHeader {
    // Define fields for DNS packet
    pub id: u16,      // Identifier, 16 bits
    pub qr: bool,     // Query or Response, 1 bit
    pub opcode: u8,   // Operation code, 4 bits
    pub aa: bool,     // Authoritative answer, 1 bit
    pub tc: bool,     // Truncated, 1 bit
    pub rd: bool,     // Recursion desired, 1 bit
    pub ra: bool,     // Recursion available, 1 bit
    pub z: u8,        // Reserved for future use, 3 bits
    pub rcode: u8,    // Response code, 4 bits
    pub qdcount: u16, // Number of questions, 16 bits
    pub ancount: u16, // Number of answers, 16 bits
    pub nscount: u16, // Number of authority records, 16 bits
    pub arcount: u16, // Number of additional records, 16 bits
}

// Define the DNS question section structure
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String, // Domain name, represented as a sequence of "labels"
    pub qtype: u16, // Query type (e.g., A, AAAA, CNAME) https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
    pub qclass: u16, // Query class (e.g., IN for Internet) https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
}

// imlpement the Display trait for DnsQuestion
impl std::fmt::Display for DnsQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.name, self.qtype, self.qclass)
    }
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsPacketHeader,
    // Additional fields here for questions, answers, authorities, and additionals
    // For example:
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    // pub authorities: Vec<DnsResourceRecord>,
    // pub additionals: Vec<DnsResourceRecord>,
}

#[derive(Debug, Clone)]
pub struct DnsResourceRecord {
    pub name: String,   // The domain name encoded as a sequence of labels
    pub rtype: u16, // Resource type (e.g., A, AAAA, CNAME) https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
    pub rclass: u16, // Resource class (e.g., IN for Internet)
    pub ttl: u32,   // Time to live in seconds
    pub rdlength: u16, // Length of the resource data in bytes
    pub rdata: Vec<u8>, // Resource data (variable length)
}

// Setup the DnsResourceRecord builder
impl DnsResourceRecord {
    pub fn new(name: String, rtype: u16, rclass: u16, ttl: u32, rdata: Vec<u8>) -> Self {
        let rdlength = rdata.len() as u16;
        DnsResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata,
        }
    }
}
