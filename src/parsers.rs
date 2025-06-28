use nom::{
    self,
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};

use crate::protocol::{DnsPacket, DnsPacketHeader, DnsQuestion};
// use tracing::debug;

pub fn parse_dns_packet_header(input: &[u8]) -> IResult<&[u8], DnsPacketHeader> {
    let (input, id) = be_u16(input)?;
    // take 1 bit for qr, 4 bits for opcode, 1 bit for aa,
    // 1 bit for tc, 1 bit for rd, 1 bit for ra, 3 bits for z,
    // and 4 bits for rcode
    let (input, flags) = be_u16(input)?;
    let (input, qdcount) = be_u16(input)?;
    let (input, ancount) = be_u16(input)?;
    let (input, nscount) = be_u16(input)?;
    let (input, arcount) = be_u16(input)?;

    let header = DnsPacketHeader {
        id,
        // qr (Query/Response): (flags & 0x8000) != 0
        qr: (flags & 0x8000) != 0,
        // opcode: bits 11-14
        opcode: ((flags & 0x7800) >> 11) as u8,
        // aa (Authoritative Answer): bit 10
        aa: (flags & 0x0400) != 0,
        // tc (Truncated): bit 9
        tc: (flags & 0x0200) != 0,
        // rd (Recursion Desired): bit 8
        rd: (flags & 0x0100) != 0,
        // ra (Recursion Available): bit 7
        ra: (flags & 0x0080) != 0,
        // z (Reserved for future use): bits 4-6
        z: ((flags & 0x0070) >> 4) as u8,
        // rcode (Response Code): bits 0-3
        rcode: (flags & 0x000F) as u8,
        qdcount,
        ancount,
        nscount,
        arcount,
    };

    Ok((input, header))
}

/// Recursively parses a domain name, handling the DNS compression scheme.
/// where 'p: 'i: This constraint means lifetime 'p must outlive lifetime 'i.
/// This ensures that the full packet reference remains valid for at least
/// as long as the input slice reference.
fn parse_name_recursive<'p, 'i>(
    full_packet: &'p [u8],
    input: &'i [u8],
) -> IResult<&'i [u8], Vec<String>>
where
    'p: 'i,
{
    let (i, length) = be_u8(input)?;

    match length {
        l if (l & 0b1100_0000) == 0b1100_0000 => {
            let (i, next_byte) = be_u8(i)?;
            let offset = u16::from_be_bytes([l, next_byte]) & 0x3FFF;
            let (_, labels) = parse_name_recursive(full_packet, &full_packet[offset as usize..])?;
            Ok((i, labels))
        }
        0 => Ok((i, Vec::new())),
        l if l <= 63 => {
            let (i, label_bytes) = take(l as usize)(i)?;
            let label = String::from_utf8_lossy(label_bytes).to_string();
            let (i, mut next_labels) = parse_name_recursive(full_packet, i)?;
            let mut labels = vec![label];
            labels.append(&mut next_labels);
            Ok((i, labels))
        }
        _ => Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }
}

/// Public-facing parser for a domain name.
fn parse_domain_name<'p, 'i>(full_packet: &'p [u8], input: &'i [u8]) -> IResult<&'i [u8], String>
where
    'p: 'i,
{
    let (i, labels) = parse_name_recursive(full_packet, input)?;
    Ok((i, labels.join(".")))
}

/// Parse a complete DNS question section, requires the full packet for compression.
fn parse_dns_question<'p, 'i>(
    full_packet: &'p [u8],
    input: &'i [u8],
) -> IResult<&'i [u8], DnsQuestion>
where
    'p: 'i,
{
    let (input, name) = parse_domain_name(full_packet, input)?;
    let (input, qtype) = be_u16(input)?;
    let (input, qclass) = be_u16(input)?;

    Ok((
        input,
        DnsQuestion {
            name,
            qtype,
            qclass,
        },
    ))
}

// Parse a complete DNS packet
pub fn parse_dns_packet(input: &[u8]) -> IResult<&[u8], DnsPacket> {
    // Keep a reference to the start of the packet for handling compression offsets.
    let full_packet = input;

    // Parse the DNS packet header
    let (mut remaining_input, header) = parse_dns_packet_header(full_packet)?;

    // To avoid complex lifetime issues with nom's `count` combinator and older
    // versions of the library, we can simply loop and call our parser manually.
    let mut questions = Vec::with_capacity(header.qdcount as usize);
    for _ in 0..header.qdcount {
        let (i, question) = parse_dns_question(full_packet, remaining_input)?;
        questions.push(question);
        remaining_input = i;
    }

    // Here we would continue parsing the answers, authorities, and additionals.
    let packet = DnsPacket {
        header,
        questions,
        answers: Vec::new(), // Placeholder for answer parsing
    };

    Ok((remaining_input, packet))
}
