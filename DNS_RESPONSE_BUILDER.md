# DNS Response Builder

This project includes an enhanced DNS Response Builder that provides efficient and flexible ways to create DNS response packets with custom domains and minimal memory allocation.

## Key Features

- **Zero-clone response creation** when taking ownership of query packets
- **Copy semantics** for DNS headers (no heap allocation)
- **Reusable builder** instance for multiple requests
- **Custom domain support** with proper DNS record types
- **Fluent interface** for readable, chainable method calls

## DNS Record Type Constants

```rust
use response_builder::*;

// Available DNS record types
DNS_TYPE_A      // IPv4 address (1)
DNS_TYPE_NS     // Name server (2)
DNS_TYPE_CNAME  // Canonical name (5)
DNS_TYPE_SOA    // Start of authority (6)
DNS_TYPE_PTR    // Pointer record (12)
DNS_TYPE_MX     // Mail exchange (15)
DNS_TYPE_TXT    // Text record (16)
DNS_TYPE_AAAA   // IPv6 address (28)

DNS_CLASS_IN    // Internet class (1)
```

## Usage Examples

### 1. Basic Response Builder Setup

```rust
use response_builder::DnsResponseBuilder;

let mut builder = DnsResponseBuilder::new();
```

### 2. Simple Domain Response

```rust
// Create a response for a single domain (A record)
let response = builder.build_domain_response("google.com", 1234);

// This creates a DNS response with:
// - Query ID: 1234
// - Question: google.com A record
// - Answer count: 1
```

### 3. Multiple Domains Response

```rust
// Create response for multiple domains
let domains = ["google.com", "facebook.com", "github.com"];
let response = builder.build_multi_domain_response(&domains, 5678);

// This creates a DNS response with:
// - Query ID: 5678
// - Questions: All three domains as A records
// - Answer count: 3
```

### 4. Fluent Interface with Custom Domains

```rust
// Using the fluent interface for custom responses
let response = builder
    .build_custom_response(&query_packet)
    .with_a_record("google.com")        // A record for IPv4
    .with_authoritative(true)           // Set as authoritative
    .with_rcode(0)                      // NOERROR response code
    .build();
```

### 5. Different DNS Record Types

```rust
// IPv6 address lookup (AAAA record)
let response = builder
    .build_custom_response(&query)
    .with_aaaa_record("ipv6.google.com")
    .build();

// Canonical name lookup (CNAME record)
let response = builder
    .build_custom_response(&query)
    .with_cname_record("www.example.com")
    .build();

// Mail exchange lookup (MX record)
let response = builder
    .build_custom_response(&query)
    .with_mx_record("mail.example.com")
    .build();

// Text record lookup (TXT record)
let response = builder
    .build_custom_response(&query)
    .with_txt_record("verification.example.com")
    .build();
```

### 6. Custom Question with Specific Types

```rust
// Add a custom question with specific record type and class
let response = builder
    .build_custom_response(&query)
    .with_question("example.com", DNS_TYPE_A, DNS_CLASS_IN)
    .with_authoritative(false)
    .build();
```

### 7. Error Responses

```rust
// Create an NXDOMAIN (domain not found) response
let error_response = builder
    .build_custom_response(&query)
    .with_a_record("nonexistent.com")
    .with_rcode(3)  // NXDOMAIN
    .with_authoritative(true)
    .build();

// Create a SERVFAIL response
let error_response = builder
    .build_custom_response(&query)
    .with_rcode(2)  // SERVFAIL
    .build();
```

### 8. Integration in Main Server Loop

```rust
// In your main DNS server loop
let mut response_builder = DnsResponseBuilder::new();

loop {
    // ... receive and decode DNS packet ...
    
    match codec.decode(&mut bytes_mut) {
        Ok(Some(packet)) => {
            // Option 1: Simple response echoing the query
            let response_packet = create_dns_response(packet);
            
            // Option 2: Using builder with custom domain
            let response_packet = response_builder
                .build_custom_response(&packet)
                .with_a_record("google.com")
                .with_rcode(0)
                .with_authoritative(false)
                .build();
            
            // Option 3: Direct domain response
            let response_packet = response_builder
                .build_domain_response("example.com", packet.header.id);
            
            // ... encode and send response ...
        }
    }
}
```

## Performance Benefits

1. **Reduced Memory Allocation**: Headers use copy semantics instead of cloning
2. **Reusable Builder**: One builder instance can create multiple responses
3. **Efficient Domain Handling**: Proper DNS record type support
4. **Zero-Clone Option**: When taking ownership of query packets

## Testing

Run the comprehensive test suite:

```bash
cargo test response_builder
```

The tests cover:
- Basic response building
- Custom domain responses
- Multiple domain responses
- Different DNS record types
- Fluent interface functionality
- Error handling scenarios
