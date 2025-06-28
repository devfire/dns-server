//! DNS packet codec for tokio_util
//!
//! This module provides Decoder and Encoder implementations for DNS packets,
//! allowing integration with tokio's framed streams and UDP handling.

use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, error};

use crate::errors::DnsCodecError;
use crate::parsers::parse_dns_packet;
use crate::protocol::DnsPacket;

/// DNS packet codec for use with tokio_util framed streams
#[derive(Debug, Default)]
pub struct DnsCodec;

impl DnsCodec {
    /// Create a new DNS codec instance
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for DnsCodec {
    type Item = DnsPacket;
    type Error = DnsCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // debug!("DnsCodec::decode called with {} bytes", src.len());

        // DNS packets need at least 12 bytes for the header
        if src.len() < 12 {
            debug!("Insufficient bytes for DNS header: {} < 12", src.len());
            return Ok(None);
        }

        // For UDP DNS packets, we expect complete packets in each datagram
        // Convert BytesMut to &[u8] for nom parsing
        let input_bytes = src.as_ref();

        // debug!(
        //     "Attempting to parse DNS packet of {} bytes",
        //     input_bytes.len()
        // );

        // Use our existing nom parser
        match parse_dns_packet(input_bytes) {
            Ok((remaining, packet)) => {
                let consumed = input_bytes.len() - remaining.len();
                // debug!(
                //     "Successfully parsed DNS packet, consumed {} bytes",
                //     consumed
                // );

                // Remove the consumed bytes from the buffer
                let _ = src.split_to(consumed);

                Ok(Some(packet))
            }
            Err(nom::Err::Incomplete(needed)) => {
                debug!("Incomplete DNS packet, need more data: {:?}", needed);

                let needed_bytes = match needed {
                    nom::Needed::Size(n) => n.get(),
                    nom::Needed::Unknown => 64, // Reasonable default for DNS
                };

                Err(DnsCodecError::IncompletePacket {
                    needed: needed_bytes,
                    available: src.len(),
                })
            }
            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
                error!("DNS parsing error: {:?}", e);

                // Convert nom error to our error type
                let error_msg = format!("nom parsing failed: {:?}", e);
                Err(DnsCodecError::NomError(error_msg))
            }
        }
    }
}

impl Encoder<DnsPacket> for DnsCodec {
    type Error = DnsCodecError;

    fn encode(&mut self, item: DnsPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("DnsCodec::encode called for packet ID {}", item.header.id);

        // Create a corrected header with the actual question and answer counts
        let mut corrected_header = item.header;
        corrected_header.qdcount = item.questions.len() as u16;
        corrected_header.ancount = item.answers.len() as u16;

        // Encode DNS packet header (12 bytes) with corrected counts
        self.encode_header(&corrected_header, dst);

        // Encode the questions
        for question in &item.questions {
            // Encode the question name using DNS label format
            self.encode_domain_name(&question.name, dst)?;

            // Encode the question type (2 bytes)
            dst.put_u16(question.qtype);

            // Encode the question class (2 bytes)
            dst.put_u16(question.qclass);
        }

        // Encode the answers
        for answer in &item.answers {
            // Encode the answer name using DNS label format
            self.encode_domain_name(&answer.name, dst)?;

            // Encode the answer type (2 bytes)
            dst.put_u16(answer.rtype);

            // Encode the answer class (2 bytes)
            dst.put_u16(answer.rclass);

            // Encode the TTL (4 bytes)
            dst.put_u32(answer.ttl);

            // Encode the data length (2 bytes)
            dst.put_u16(answer.rdata.len() as u16);

            // Encode the data
            dst.put_slice(&answer.rdata);
        }

        // debug!(
        //     "Successfully encoded DNS packet, total size: {} bytes",
        //     dst.len()
        // );
        Ok(())
    }
}

impl DnsCodec {
    /// Encode a DNS domain name using label format
    /// Domain names are encoded as a sequence of labels, each prefixed by its length,
    /// terminated by a null byte (0)
    fn encode_domain_name(
        &self,
        domain_name: &str,
        dst: &mut BytesMut,
    ) -> Result<(), DnsCodecError> {
        // Split the domain name by dots to get individual labels
        let labels: Vec<&str> = domain_name.split('.').collect();

        // Calculate total space needed: sum of (1 byte length + label bytes) + 1 null terminator
        let total_space: usize = labels.iter().map(|label| 1 + label.len()).sum::<usize>() + 1;
        dst.reserve(total_space);

        // Encode each label
        for label in labels {
            // Check label length (DNS labels must be <= 63 bytes)
            if label.len() > 63 {
                return Err(DnsCodecError::InvalidDomainName(format!(
                    "Label '{}' exceeds maximum length of 63 bytes",
                    label
                )));
            }

            // Skip empty labels (e.g., from trailing dots)
            if label.is_empty() {
                continue;
            }

            // Encode length byte followed by label content
            dst.put_u8(label.len() as u8);
            dst.put_slice(label.as_bytes());
        }

        // Null terminator
        dst.put_u8(0);

        Ok(())
    }

    /// Encode DNS packet header into the destination buffer
    fn encode_header(&self, header: &crate::protocol::DnsPacketHeader, dst: &mut BytesMut) {
        // Ensure we have enough space (12 bytes for header)
        dst.reserve(12);

        // ID (16 bits)
        dst.put_u16(header.id);

        // Flags (16 bits total)
        let mut flags: u16 = 0;

        // QR (1 bit) - bit 15
        if header.qr {
            flags |= 0x8000;
        }

        // OPCODE (4 bits) - bits 14-11
        flags |= ((header.opcode as u16) & 0x0F) << 11;

        // AA (1 bit) - bit 10
        if header.aa {
            flags |= 0x0400;
        }

        // TC (1 bit) - bit 9
        if header.tc {
            flags |= 0x0200;
        }

        // RD (1 bit) - bit 8
        if header.rd {
            flags |= 0x0100;
        }

        // RA (1 bit) - bit 7
        if header.ra {
            flags |= 0x0080;
        }

        // Z (3 bits) - bits 6-4 (reserved, should be 0)
        flags |= ((header.z as u16) & 0x07) << 4;

        // RCODE (4 bits) - bits 3-0
        flags |= (header.rcode as u16) & 0x0F;

        dst.put_u16(flags);

        // Question count (16 bits)
        dst.put_u16(header.qdcount);

        // Answer count (16 bits)
        dst.put_u16(header.ancount);

        // Authority count (16 bits)
        dst.put_u16(header.nscount);

        // Additional count (16 bits)
        dst.put_u16(header.arcount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_dns_codec_insufficient_bytes() {
        let mut codec = DnsCodec::new();
        let mut buf = BytesMut::from(&b"short"[..]);

        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_dns_codec_empty_buffer() {
        let mut codec = DnsCodec::new();
        let mut buf = BytesMut::new();

        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_dns_codec_encode_header() {
        use crate::protocol::{DnsPacket, DnsPacketHeader};

        let mut codec = DnsCodec::new();
        let mut buf = BytesMut::new();

        let header = DnsPacketHeader {
            id: 0x1234,
            qr: true,  // Response
            opcode: 0, // QUERY
            aa: true,  // Authoritative
            tc: false, // Not truncated
            rd: true,  // Recursion desired
            ra: true,  // Recursion available
            z: 0,      // Reserved
            rcode: 0,  // NOERROR
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };

        let packet = DnsPacket {
            header,
            questions: vec![], // Empty questions for this test
            answers: vec![],   // Empty answers for this test
        };

        let result = codec.encode(packet, &mut buf);
        assert!(result.is_ok());
        assert_eq!(buf.len(), 12); // Header is 12 bytes

        // Verify the encoded bytes
        let bytes = buf.as_ref();

        // ID should be 0x1234
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 0x34);

        // Flags should have QR=1, AA=1, RD=1, RA=1
        // Expected: 0x8580 (binary: 1000 0101 1000 0000)
        assert_eq!(bytes[2], 0x85);
        assert_eq!(bytes[3], 0x80);

        // QDCOUNT should be 0 (corrected from header's 1 to match actual questions count)
        assert_eq!(bytes[4], 0x00);
        assert_eq!(bytes[5], 0x00);

        // ANCOUNT should be 0 (corrected from header's 1 to match actual answers count)
        assert_eq!(bytes[6], 0x00);
        assert_eq!(bytes[7], 0x00);
    }

    #[test]
    fn test_dns_codec_encode_with_questions() {
        use crate::protocol::{DnsPacket, DnsPacketHeader, DnsQuestion};

        let mut codec = DnsCodec::new();
        let mut buf = BytesMut::new();

        let header = DnsPacketHeader {
            id: 0x1234,
            qr: false,  // Query
            opcode: 0,  // QUERY
            aa: false,  // Not authoritative
            tc: false,  // Not truncated
            rd: true,   // Recursion desired
            ra: false,  // Recursion not available
            z: 0,       // Reserved
            rcode: 0,   // NOERROR
            qdcount: 1, // One question
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let question = DnsQuestion {
            name: "google.com".to_string(),
            qtype: 1,  // A record
            qclass: 1, // IN class
        };

        let packet = DnsPacket {
            header,
            questions: vec![question],
            answers: vec![],
        };

        let result = codec.encode(packet, &mut buf);
        assert!(result.is_ok());

        let bytes = buf.as_ref();

        // Verify header (12 bytes)
        assert_eq!(bytes[0], 0x12); // ID high byte
        assert_eq!(bytes[1], 0x34); // ID low byte

        // Verify flags (RD=1, others=0)
        assert_eq!(bytes[2], 0x01); // High byte: 00000001
        assert_eq!(bytes[3], 0x00); // Low byte: 00000000

        // Verify counts
        assert_eq!(bytes[4], 0x00); // QDCOUNT high
        assert_eq!(bytes[5], 0x01); // QDCOUNT low = 1
        assert_eq!(bytes[6], 0x00); // ANCOUNT high
        assert_eq!(bytes[7], 0x00); // ANCOUNT low = 0

        // Verify question section starts at byte 12
        // "google.com" should be encoded as:
        // 6 + "google" + 3 + "com" + 0
        assert_eq!(bytes[12], 6); // Length of "google"
        assert_eq!(&bytes[13..19], b"google"); // "google"
        assert_eq!(bytes[19], 3); // Length of "com"
        assert_eq!(&bytes[20..23], b"com"); // "com"
        assert_eq!(bytes[23], 0); // Null terminator

        // Verify QTYPE (A record = 1)
        assert_eq!(bytes[24], 0x00); // QTYPE high
        assert_eq!(bytes[25], 0x01); // QTYPE low = 1

        // Verify QCLASS (IN = 1)
        assert_eq!(bytes[26], 0x00); // QCLASS high
        assert_eq!(bytes[27], 0x01); // QCLASS low = 1

        // Total expected length: 12 (header) + 12 (question name) + 4 (qtype + qclass) = 28
        assert_eq!(bytes.len(), 28);
    }

    #[test]
    fn test_dns_codec_encode_domain_name_edge_cases() {
        let codec = DnsCodec::new();
        let mut buf = BytesMut::new();

        // Test simple domain
        let result = codec.encode_domain_name("example.com", &mut buf);
        assert!(result.is_ok());

        let expected = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            3, b'c', b'o', b'm', // "com"
            0,    // null terminator
        ];
        assert_eq!(buf.as_ref(), &expected[..]);

        // Test domain with trailing dot (should be handled correctly)
        buf.clear();
        let result = codec.encode_domain_name("test.org.", &mut buf);
        assert!(result.is_ok());

        let expected = vec![
            4, b't', b'e', b's', b't', // "test"
            3, b'o', b'r', b'g', // "org"
            0,    // null terminator
        ];
        assert_eq!(buf.as_ref(), &expected[..]);
    }

    #[test]
    fn test_dns_codec_round_trip_single_question() {
        use crate::protocol::{DnsPacket, DnsPacketHeader, DnsQuestion};

        let mut codec = DnsCodec::new();

        // Create a test packet with a single question
        let original_packet = DnsPacket {
            header: DnsPacketHeader {
                id: 0x1234,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1, // One question
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                name: "example.com".to_string(),
                qtype: 1,  // A record
                qclass: 1, // IN class
            }],
            answers: vec![],
        };

        // Encode the packet
        let mut encoded_buf = BytesMut::new();
        let encode_result = codec.encode(original_packet.clone(), &mut encoded_buf);
        assert!(encode_result.is_ok());

        // Decode the packet back
        let mut decode_buf = encoded_buf.clone();
        let decode_result = codec.decode(&mut decode_buf);
        assert!(decode_result.is_ok());

        let decoded_packet = decode_result.unwrap().unwrap();

        // Verify the round trip worked
        assert_eq!(decoded_packet.header.id, original_packet.header.id);
        assert_eq!(decoded_packet.header.qr, original_packet.header.qr);
        assert_eq!(decoded_packet.header.rd, original_packet.header.rd);
        assert_eq!(
            decoded_packet.header.qdcount,
            original_packet.header.qdcount
        );
        assert_eq!(
            decoded_packet.questions.len(),
            original_packet.questions.len()
        );

        for (decoded_q, original_q) in decoded_packet
            .questions
            .iter()
            .zip(original_packet.questions.iter())
        {
            assert_eq!(decoded_q.name, original_q.name);
            assert_eq!(decoded_q.qtype, original_q.qtype);
            assert_eq!(decoded_q.qclass, original_q.qclass);
        }
    }

    #[test]
    fn test_dns_codec_round_trip_multiple_questions() {
        use crate::protocol::{DnsPacket, DnsPacketHeader, DnsQuestion};

        let mut codec = DnsCodec::new();

        // Create a test packet with multiple questions
        let original_packet = DnsPacket {
            header: DnsPacketHeader {
                id: 0x5678,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 2, // Two questions
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![
                DnsQuestion {
                    name: "example.com".to_string(),
                    qtype: 1,  // A record
                    qclass: 1, // IN class
                },
                DnsQuestion {
                    name: "test.org".to_string(),
                    qtype: 28, // AAAA record
                    qclass: 1, // IN class
                },
            ],
            answers: vec![],
        };

        // Encode the packet
        let mut encoded_buf = BytesMut::new();
        let encode_result = codec.encode(original_packet.clone(), &mut encoded_buf);
        assert!(encode_result.is_ok());

        // Decode the packet back
        let mut decode_buf = encoded_buf.clone();
        let decode_result = codec.decode(&mut decode_buf);
        assert!(decode_result.is_ok());

        let decoded_packet = decode_result.unwrap().unwrap();

        // Verify the round trip worked
        assert_eq!(decoded_packet.header.id, original_packet.header.id);
        assert_eq!(decoded_packet.header.qr, original_packet.header.qr);
        assert_eq!(decoded_packet.header.rd, original_packet.header.rd);
        assert_eq!(
            decoded_packet.header.qdcount,
            original_packet.header.qdcount
        );
        assert_eq!(
            decoded_packet.questions.len(),
            original_packet.questions.len()
        );

        for (decoded_q, original_q) in decoded_packet
            .questions
            .iter()
            .zip(original_packet.questions.iter())
        {
            assert_eq!(decoded_q.name, original_q.name);
            assert_eq!(decoded_q.qtype, original_q.qtype);
            assert_eq!(decoded_q.qclass, original_q.qclass);
        }
    }

    #[test]
    fn test_dns_codec_qdcount_correction() {
        use crate::protocol::{DnsPacket, DnsPacketHeader, DnsQuestion};

        let mut codec = DnsCodec::new();

        // Create a packet where the header QDCOUNT doesn't match the actual questions count
        let packet = DnsPacket {
            header: DnsPacketHeader {
                id: 0x1234,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 99, // Incorrect count - should be corrected to 3
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![
                DnsQuestion {
                    name: "example.com".to_string(),
                    qtype: 1,
                    qclass: 1,
                },
                DnsQuestion {
                    name: "test.org".to_string(),
                    qtype: 28,
                    qclass: 1,
                },
                DnsQuestion {
                    name: "foo.bar".to_string(),
                    qtype: 1,
                    qclass: 1,
                },
            ],
            answers: vec![],
        };

        // Encode the packet
        let mut encoded_buf = BytesMut::new();
        let encode_result = codec.encode(packet, &mut encoded_buf);
        assert!(encode_result.is_ok());

        // Check that the encoded QDCOUNT field is correct (should be 3, not 99)
        let bytes = encoded_buf.as_ref();

        // QDCOUNT is at bytes 4-5 (after ID and flags)
        let qdcount_encoded = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(
            qdcount_encoded, 3,
            "QDCOUNT should be corrected to match actual questions count"
        );

        // Decode and verify the packet works correctly
        let mut decode_buf = encoded_buf.clone();
        let decode_result = codec.decode(&mut decode_buf);
        assert!(decode_result.is_ok());

        let decoded_packet = decode_result.unwrap().unwrap();
        assert_eq!(decoded_packet.header.qdcount, 3);
        assert_eq!(decoded_packet.questions.len(), 3);
    }

    #[test]
    fn test_dns_codec_encode_with_answers() {
        use crate::protocol::{DnsPacket, DnsPacketHeader, DnsQuestion, DnsResourceRecord};

        let mut codec = DnsCodec::new();
        let mut buf = BytesMut::new();

        let header = DnsPacketHeader {
            id: 0x5678,
            qr: true,   // Response
            opcode: 0,  // QUERY
            aa: true,   // Authoritative
            tc: false,  // Not truncated
            rd: true,   // Recursion desired
            ra: true,   // Recursion available
            z: 0,       // Reserved
            rcode: 0,   // NOERROR
            qdcount: 1, // One question
            ancount: 1, // One answer
            nscount: 0,
            arcount: 0,
        };

        let question = DnsQuestion {
            name: "example.com".to_string(),
            qtype: 1,  // A record
            qclass: 1, // IN class
        };

        let answer = DnsResourceRecord::new(
            "example.com".to_string(),
            crate::response_builder::DNS_TYPE_A,
            crate::response_builder::DNS_CLASS_IN,
            300,
            vec![192, 168, 1, 1],
        );

        let packet = DnsPacket {
            header,
            questions: vec![question],
            answers: vec![answer],
        };

        let result = codec.encode(packet, &mut buf);
        assert!(result.is_ok());

        let bytes = buf.as_ref();

        // Verify header (12 bytes)
        assert_eq!(bytes[0], 0x56); // ID high byte
        assert_eq!(bytes[1], 0x78); // ID low byte

        // Verify flags (QR=1, AA=1, RD=1, RA=1)
        // Expected: 0x8580 (binary: 1000 0101 1000 0000)
        assert_eq!(bytes[2], 0x85);
        assert_eq!(bytes[3], 0x80);

        // Verify counts
        assert_eq!(bytes[4], 0x00); // QDCOUNT high
        assert_eq!(bytes[5], 0x01); // QDCOUNT low = 1
        assert_eq!(bytes[6], 0x00); // ANCOUNT high
        assert_eq!(bytes[7], 0x01); // ANCOUNT low = 1

        // Question section starts at byte 12
        // "example.com" = 7 + "example" + 3 + "com" + 0 = 13 bytes
        // QTYPE (2 bytes) + QCLASS (2 bytes) = 4 bytes
        // Total question section = 17 bytes
        let answer_start = 12 + 17; // 29

        // Verify answer section starts at byte 29
        // Answer name: "example.com" (same encoding as question)
        assert_eq!(bytes[answer_start], 7); // Length of "example"
        assert_eq!(&bytes[answer_start + 1..answer_start + 8], b"example");
        assert_eq!(bytes[answer_start + 8], 3); // Length of "com"
        assert_eq!(&bytes[answer_start + 9..answer_start + 12], b"com");
        assert_eq!(bytes[answer_start + 12], 0); // Null terminator

        let rtype_start = answer_start + 13;
        // Verify RTYPE (A record = 1)
        assert_eq!(bytes[rtype_start], 0x00); // RTYPE high
        assert_eq!(bytes[rtype_start + 1], 0x01); // RTYPE low = 1

        // Verify RCLASS (IN = 1)
        assert_eq!(bytes[rtype_start + 2], 0x00); // RCLASS high
        assert_eq!(bytes[rtype_start + 3], 0x01); // RCLASS low = 1

        // Verify TTL (300 seconds)
        let ttl_bytes = &bytes[rtype_start + 4..rtype_start + 8];
        let ttl = u32::from_be_bytes([ttl_bytes[0], ttl_bytes[1], ttl_bytes[2], ttl_bytes[3]]);
        assert_eq!(ttl, 300);

        // Verify data length (4 bytes for IPv4)
        assert_eq!(bytes[rtype_start + 8], 0x00); // Length high
        assert_eq!(bytes[rtype_start + 9], 0x04); // Length low = 4

        // Verify data (IP address 192.168.1.1)
        assert_eq!(bytes[rtype_start + 10], 192);
        assert_eq!(bytes[rtype_start + 11], 168);
        assert_eq!(bytes[rtype_start + 12], 1);
        assert_eq!(bytes[rtype_start + 13], 1);

        // Total expected length: 12 (header) + 17 (question) + 27 (answer) = 56
        assert_eq!(bytes.len(), 56);
    }
}
