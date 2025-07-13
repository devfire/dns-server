use crate::protocol::{DnsPacket, DnsPacketHeader, DnsQuestion, DnsResourceRecord};
use std::net::{IpAddr, Ipv6Addr};

// DNS Record Type Constants
pub const DNS_TYPE_A: u16 = 1; // IPv4 address
pub const DNS_TYPE_NS: u16 = 2; // Name server
pub const DNS_TYPE_CNAME: u16 = 5; // Canonical name
pub const DNS_TYPE_SOA: u16 = 6; // Start of authority
pub const DNS_TYPE_PTR: u16 = 12; // Pointer record
pub const DNS_TYPE_MX: u16 = 15; // Mail exchange
pub const DNS_TYPE_TXT: u16 = 16; // Text record
pub const DNS_TYPE_AAAA: u16 = 28; // IPv6 address

// DNS Class Constants
pub const DNS_CLASS_IN: u16 = 1; // Internet

/// Builder for creating DNS response packets efficiently
pub struct DnsResponseBuilder {
    // Pre-allocated response header template
    response_header: DnsPacketHeader,
    // Reusable questions vector
    questions: Vec<DnsQuestion>,
    // Reusable answers vector
    answers: Vec<DnsResourceRecord>,
}

impl DnsResponseBuilder {
    /// Create a new response builder
    pub fn new() -> Self {
        Self {
            response_header: DnsPacketHeader {
                id: 0,
                qr: true,  // Always a response
                opcode: 0, // QUERY
                aa: false, // Not authoritative by default
                tc: false, // Not truncated
                rd: false, // Will be copied from query
                ra: true,  // Recursion available
                z: 0,      // Reserved
                rcode: 0,  // NOERROR by default
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }

    /// Get the current number of answers (for debugging)
    pub fn answers_count(&self) -> usize {
        self.answers.len()
    }

    /// Clear accumulated answers (for reusing builder)
    pub fn clear_answers(&mut self) {
        self.answers.clear();
    }

    /// Build a response from a query packet without cloning
    pub fn build_response(&mut self, query_packet: &DnsPacket) -> DnsPacket {
        // Copy primitive fields (no heap allocation)
        self.response_header.id = query_packet.header.id; // Echo the query ID
        self.response_header.rd = query_packet.header.rd; // Copy recursion desired
        self.response_header.qdcount = query_packet.header.qdcount;
        self.response_header.ancount = query_packet.header.qdcount; // Answer count = question count

        DnsPacket {
            header: self.response_header,
            questions: query_packet.questions.clone(), // Still need to clone here for ownership
            answers: self.answers.clone(),
        }
    }

    /// More efficient version that takes ownership and reuses the packet
    // pub fn build_response_owned(&mut self, mut query_packet: DnsPacket) -> DnsPacket {
    //     // Modify the header in place
    //     query_packet.header.qr = true;
    //     query_packet.header.aa = false;
    //     query_packet.header.ra = true;
    //     query_packet.header.rcode = 0;
    //     query_packet.header.ancount = query_packet.header.qdcount;

    //     query_packet
    // }

    /// Build response with custom settings
    pub fn build_custom_response<'a>(
        &'a mut self,
        query_packet: &'a DnsPacket,
    ) -> ResponseBuilder<'a> {
        ResponseBuilder {
            builder: self,
            query_packet,
        }
    }

    /// Create a response for a specific domain query (A record)
    pub fn build_domain_response(
        &mut self,
        domain: &str,
        dns_resource_record: DnsResourceRecord,
        query_id: u16,
    ) -> DnsPacket {
        self.response_header.id = query_id;
        self.response_header.qdcount = 1;
        self.response_header.ancount = 1;

        let question = DnsQuestion {
            name: domain.to_string(),
            qtype: 1,  // A record
            qclass: 1, // IN (Internet)
        };

        DnsPacket {
            header: self.response_header,
            questions: vec![question],
            answers: vec![dns_resource_record], // Convert to Vec<DnsResourceRecord>
        }
    }

    // Create a response for multiple domains
    // pub fn build_multi_domain_response(&mut self, domains: &[&str], query_id: u16) -> DnsPacket {
    //     self.response_header.id = query_id;
    //     self.response_header.qdcount = domains.len() as u16;
    //     self.response_header.ancount = domains.len() as u16;

    //     let questions: Vec<DnsQuestion> = domains
    //         .iter()
    //         .map(|domain| DnsQuestion {
    //             name: domain.to_string(),
    //             qtype: 1,  // A record
    //             qclass: 1, // IN (Internet)
    //         })
    //         .collect();

    //     DnsPacket {
    //         header: self.response_header,
    //         questions,
    //     }
    // }
}

/// Fluent interface for building custom responses
pub struct ResponseBuilder<'a> {
    builder: &'a mut DnsResponseBuilder,
    query_packet: &'a DnsPacket,
}

impl<'a> ResponseBuilder<'a> {
    // /// Get the current number of answers (for debugging)
    // pub fn answers_count(&self) -> usize {
    //     self.builder.answers.len()
    // }

    /// Set response code
    pub fn with_rcode(self, rcode: u8) -> Self {
        self.builder.response_header.rcode = rcode;
        self
    }

    /// Set qr (query/response) flag
    pub fn with_qr(self, qr: bool) -> Self {
        self.builder.response_header.qr = qr;
        self
    }

    /// Set reserved bits (z)
    pub fn with_z(self, z: u8) -> Self {
        self.builder.response_header.z = z;
        self
    }

    /// Set authoritative flag
    pub fn with_authoritative(self, aa: bool) -> Self {
        self.builder.response_header.aa = aa;
        self
    }

    /// Set recursion available flag
    pub fn with_recursion_available(self, ra: bool) -> Self {
        self.builder.response_header.ra = ra;
        self
    }

    /// Add a custom question to the response
    pub fn with_question(self, domain: &str, qtype: u16, qclass: u16) -> Self {
        let question = DnsQuestion {
            name: domain.to_string(),
            qtype,
            qclass,
        };
        self.builder.questions.clear();
        self.builder.questions.push(question);
        self.builder.response_header.qdcount = 1;
        self.builder.response_header.ancount = 1; // Assume we'll provide an answer
        self
    }

    /// Add an A record question (IPv4 address lookup)
    pub fn with_a_record(self, domain: &str) -> Self {
        self.with_question(domain, DNS_TYPE_A, DNS_CLASS_IN)
    }

    /// Add an AAAA record question (IPv6 address lookup)
    pub fn with_aaaa_record(self, domain: &str) -> Self {
        self.with_question(domain, DNS_TYPE_AAAA, DNS_CLASS_IN)
    }

    /// Add a CNAME record question (canonical name lookup)
    pub fn with_cname_record(self, domain: &str) -> Self {
        self.with_question(domain, DNS_TYPE_CNAME, DNS_CLASS_IN)
    }

    /// Add an MX record question (mail exchange lookup)
    pub fn with_mx_record(self, domain: &str) -> Self {
        self.with_question(domain, DNS_TYPE_MX, DNS_CLASS_IN)
    }

    /// Add a TXT record question (text record lookup)
    pub fn with_txt_record(self, domain: &str) -> Self {
        self.with_question(domain, DNS_TYPE_TXT, DNS_CLASS_IN)
    }

    /// Add an A record answer (IPv4 address) - automatically adds the corresponding question
    pub fn with_an_answer(self, domain: &str, ip: IpAddr, ttl: u32) -> Self {
        // First add the question (copied from with_a_record)
        let question = DnsQuestion {
            name: domain.to_string(),
            qtype: DNS_TYPE_A,
            qclass: DNS_CLASS_IN,
        };
        self.builder.questions.clear();
        self.builder.questions.push(question);
        self.builder.response_header.qdcount = 1;

        let answer: DnsResourceRecord = DnsResourceRecord::new(
            domain.to_string(),
            DNS_TYPE_A,
            DNS_CLASS_IN,
            ttl,
            match ip { // this is the resolved IP address from the query
                IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
            },
        );

        self.builder.answers.push(answer);
        self.builder.response_header.ancount = self.builder.answers.len() as u16;
        self
    }

    /// Add an AAAA record answer (IPv6 address) - automatically adds the corresponding question
    pub fn with_aaaa_answer(self, domain: &str, ip: Ipv6Addr, ttl: u32) -> Self {
        // First add the question (copied from with_aaaa_record)
        let question = DnsQuestion {
            name: domain.to_string(),
            qtype: DNS_TYPE_AAAA,
            qclass: DNS_CLASS_IN,
        };
        self.builder.questions.clear();
        self.builder.questions.push(question);
        self.builder.response_header.qdcount = 1;

        let answer: DnsResourceRecord = DnsResourceRecord::new(
            domain.to_string(),
            DNS_TYPE_AAAA,
            DNS_CLASS_IN,
            ttl,
            ip.octets().to_vec(),
        );

        self.builder.answers.push(answer);
        self.builder.response_header.ancount = self.builder.answers.len() as u16;
        self
    }

    /// Add a CNAME record answer (canonical name)
    pub fn with_cname_answer(self, domain: &str, cname: &str, ttl: u32) -> Self {
        // For CNAME, we need to encode the domain name in DNS format
        let mut data = Vec::new();
        for label in cname.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0); // Null terminator

        let answer =
            DnsResourceRecord::new(domain.to_string(), DNS_TYPE_CNAME, DNS_CLASS_IN, ttl, data);

        self.builder.answers.push(answer);
        self.builder.response_header.ancount = self.builder.answers.len() as u16;
        self
    }

    /// Add a TXT record answer (text record)
    pub fn with_txt_answer(self, domain: &str, text: &str, ttl: u32) -> Self {
        // TXT records are encoded as length-prefixed strings
        let mut data = Vec::new();
        data.push(text.len() as u8);
        data.extend_from_slice(text.as_bytes());

        let answer =
            DnsResourceRecord::new(domain.to_string(), DNS_TYPE_TXT, DNS_CLASS_IN, ttl, data);

        self.builder.answers.push(answer);
        self.builder.response_header.ancount = self.builder.answers.len() as u16;
        self
    }

    /// Add an MX record answer (mail exchange)
    pub fn with_mx_answer(self, domain: &str, priority: u16, exchange: &str, ttl: u32) -> Self {
        let mut data = Vec::new();

        // MX record format: 2-byte priority + domain name
        data.extend_from_slice(&priority.to_be_bytes());

        // Encode the exchange domain name
        for label in exchange.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0); // Null terminator

        let answer =
            DnsResourceRecord::new(domain.to_string(), DNS_TYPE_MX, DNS_CLASS_IN, ttl, data);

        self.builder.answers.push(answer);
        self.builder.response_header.ancount = self.builder.answers.len() as u16;
        self
    }

    /// Build the final response
    pub fn build(self) -> DnsPacket {
        if !self.builder.questions.is_empty() {
            // Use custom questions if they were added
            // Copy the query ID to the response
            self.builder.response_header.id = self.query_packet.header.id;
            self.builder.response_header.rd = self.query_packet.header.rd;
            self.builder.response_header.opcode = self.query_packet.header.opcode;

            // Set rcode: 0 (NOERROR) for standard query, 4 (NOTIMP) otherwise
            self.builder.response_header.rcode = match self.query_packet.header.opcode {
                0 => 0,
                _ => 4,
            };

            let built_packet = DnsPacket {
                header: self.builder.response_header,
                questions: self.builder.questions.clone(),
                answers: self.builder.answers.clone(),
            };

            tracing::debug!(
                "DNS Response built with custom settings: {:?}",
                built_packet.header
            );

            built_packet
        } else {
            // Fall back to original query questions
            self.builder.build_response(self.query_packet)
        }
    }
}

impl Default for DnsResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_builder() {
        let mut builder = DnsResponseBuilder::new();

        // Create a mock query
        let query = DnsPacket {
            header: DnsPacketHeader {
                id: 1234,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![],
            answers: vec![],
        };

        let response = builder.build_response(&query);

        assert_eq!(response.header.id, 1234);
        assert!(response.header.qr);
        assert!(response.header.ra);
        assert_eq!(response.header.ancount, 1);
    }

    #[test]
    fn test_fluent_builder() {
        let mut builder = DnsResponseBuilder::new();

        let query = DnsPacket {
            header: DnsPacketHeader {
                id: 5678,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![],
            answers: vec![],
        };

        let response = builder
            .build_custom_response(&query)
            .with_rcode(3) // NXDOMAIN
            .with_authoritative(true)
            .build();

        assert_eq!(response.header.rcode, 3);
        assert!(response.header.aa);
    }

    // #[test]
    // fn test_domain_response() {
    //     let mut builder = DnsResponseBuilder::new();

    //     let response = builder.build_domain_response("google.com", 1234);

    //     assert_eq!(response.header.id, 1234);
    //     assert!(response.header.qr);
    //     assert_eq!(response.header.qdcount, 1);
    //     assert_eq!(response.header.ancount, 1);
    //     assert_eq!(response.questions.len(), 1);
    //     assert_eq!(response.questions[0].name, "google.com");
    //     assert_eq!(response.questions[0].qtype, DNS_TYPE_A);
    //     assert_eq!(response.questions[0].qclass, DNS_CLASS_IN);
    // }

    // #[test]
    // fn test_multi_domain_response() {
    //     let mut builder = DnsResponseBuilder::new();

    //     let domains = ["google.com", "facebook.com", "github.com"];
    //     let response = builder.build_multi_domain_response(&domains, 5678);

    //     assert_eq!(response.header.id, 5678);
    //     assert_eq!(response.header.qdcount, 3);
    //     assert_eq!(response.header.ancount, 3);
    //     assert_eq!(response.questions.len(), 3);

    //     for (i, domain) in domains.iter().enumerate() {
    //         assert_eq!(response.questions[i].name, *domain);
    //         assert_eq!(response.questions[i].qtype, DNS_TYPE_A);
    //         assert_eq!(response.questions[i].qclass, DNS_CLASS_IN);
    //     }
    // }

    #[test]
    fn test_fluent_builder_with_custom_domain() {
        let mut builder = DnsResponseBuilder::new();

        let query = DnsPacket {
            header: DnsPacketHeader {
                id: 9999,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![],
            answers: vec![],
        };

        let response = builder
            .build_custom_response(&query)
            .with_a_record("example.com")
            .with_authoritative(true)
            .with_rcode(0)
            .build();

        assert_eq!(response.header.id, 9999);
        assert!(response.header.aa);
        assert_eq!(response.header.rcode, 0);
        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.questions[0].name, "example.com");
        assert_eq!(response.questions[0].qtype, DNS_TYPE_A);
    }

    #[test]
    fn test_different_record_types() {
        let mut builder = DnsResponseBuilder::new();

        let query = DnsPacket {
            header: DnsPacketHeader {
                id: 1111,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![],
            answers: vec![],
        };

        // Test AAAA record
        let response = builder
            .build_custom_response(&query)
            .with_aaaa_record("ipv6.google.com")
            .build();

        assert_eq!(response.questions[0].qtype, DNS_TYPE_AAAA);

        // Test CNAME record
        let response = builder
            .build_custom_response(&query)
            .with_cname_record("www.example.com")
            .build();

        assert_eq!(response.questions[0].qtype, DNS_TYPE_CNAME);

        // Test MX record
        let response = builder
            .build_custom_response(&query)
            .with_mx_record("mail.example.com")
            .build();

        assert_eq!(response.questions[0].qtype, DNS_TYPE_MX);

        // Test TXT record
        // let response = builder
        //     .build_custom_response(&query)
        //     .with_txt_record("verification.example.com")
        //     .build();

        // Test TXT record
        let response = builder
            .build_custom_response(&query)
            .with_txt_record("verification.example.com")
            .build();

        assert_eq!(response.questions[0].qtype, DNS_TYPE_TXT);
    }

    #[test]
    fn test_answer_records() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let query = DnsPacket {
            header: DnsPacketHeader {
                id: 2222,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![],
            answers: vec![],
        };

        // Test A record answer
        let mut builder1 = DnsResponseBuilder::new();
        let response = builder1
            .build_custom_response(&query)
            .with_a_record("example.com")
            .with_an_answer(
                "example.com",
                std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                300,
            )
            .build();

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].name, "example.com");
        assert_eq!(response.answers[0].rtype, DNS_TYPE_A);
        assert_eq!(response.answers[0].ttl, 300);
        assert_eq!(response.answers[0].rdata, vec![192, 168, 1, 1]);
        assert_eq!(response.header.ancount, 1);

        // Test AAAA record answer
        let mut builder2 = DnsResponseBuilder::new();
        let response = builder2
            .build_custom_response(&query)
            .with_aaaa_answer(
                "ipv6.example.com",
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                600,
            )
            .build();

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rtype, DNS_TYPE_AAAA);
        assert_eq!(response.answers[0].ttl, 600);

        // Test CNAME record answer
        let mut builder3 = DnsResponseBuilder::new();
        let response = builder3
            .build_custom_response(&query)
            .with_cname_record("www.example.com")
            .with_cname_answer("www.example.com", "example.com", 1800)
            .build();

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rtype, DNS_TYPE_CNAME);
        assert_eq!(response.answers[0].ttl, 1800);

        // Test TXT record answer
        let mut builder4 = DnsResponseBuilder::new();
        let response = builder4
            .build_custom_response(&query)
            .with_txt_record("verification.example.com")
            .with_txt_answer(
                "verification.example.com",
                "v=spf1 include:_spf.google.com ~all",
                3600,
            )
            .build();

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rtype, DNS_TYPE_TXT);
        assert_eq!(response.answers[0].ttl, 3600);

        // Test MX record answer
        let mut builder5 = DnsResponseBuilder::new();
        let response = builder5
            .build_custom_response(&query)
            .with_mx_record("example.com")
            .with_mx_answer("example.com", 10, "mail.example.com", 7200)
            .build();

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rtype, DNS_TYPE_MX);
        assert_eq!(response.answers[0].ttl, 7200);
        // First two bytes should be priority (10 in big-endian)
        assert_eq!(response.answers[0].rdata[0], 0);
        assert_eq!(response.answers[0].rdata[1], 10);
    }
}
