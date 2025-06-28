# Rust DNS Server

This project implements a custom DNS (Domain Name System) server in Rust, capable of handling DNS queries and providing responses. It features a robust architecture for decoding DNS packets, resolving domain names using an upstream resolver (defaulting to Google's 8.8.8.8), and constructing efficient DNS responses.

## Features

*   **Custom DNS Protocol Implementation**: Handles UDP-based DNS queries and constructs compliant DNS responses.
*   **Upstream DNS Resolution**: Forwards queries to a configurable upstream DNS resolver (e.g., 8.8.8.8) to resolve domain names.
*   **Efficient DNS Response Builder**: Utilizes a custom `DnsResponseBuilder` for creating DNS response packets with:
    *   Zero-clone response creation when taking ownership of query packets.
    *   Copy semantics for DNS headers, minimizing heap allocation.
    *   Reusable builder instance for multiple requests.
    *   Support for various DNS record types (A, AAAA, CNAME, MX, TXT, etc.).
    *   Fluent interface for readable and chainable method calls.
*   **Error Handling**: Robust error handling for decoding and encoding DNS packets, and for upstream resolution failures.
*   **Structured Logging**: Integrates `tracing` for detailed logging of server operations, packet details, and errors.
*   **Command Line Interface (CLI)**: Configurable upstream resolver via command-line arguments.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   Rust programming language (version 1.80 or newer recommended)
    *   You can install Rust using `rustup`: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/codecrafters-dns-server.git
    cd codecrafters-dns-server
    ```

2.  **Build the project:**
    ```bash
    cargo build --release
    ```

### Running the Server

The DNS server listens on `0.0.0.0:2053` by default.

```bash
cargo run --release
```

To specify a different upstream resolver (e.g., Cloudflare's 1.1.1.1):

```bash
cargo run --release -- --resolver 1.1.1.1:53
```

### Testing the Server

You can test the server using `dig` or `nslookup`.

**Using `dig`:**

```bash
dig @127.0.0.1 -p 2053 example.com
```

**Using `nslookup`:**

```bash
nslookup example.com 127.0.0.1 -port=2053
```

## Project Structure

The project is organized into several modules within the `src/` directory:

*   [`src/main.rs`](src/main.rs): The main entry point of the application, responsible for setting up the UDP socket, initializing the DNS resolver, and handling incoming DNS queries.
*   [`src/cli.rs`](src/cli.rs): Handles command-line argument parsing using `clap`.
*   [`src/codec.rs`](src/codec.rs): Implements the `DnsCodec` for encoding and decoding DNS packets using `tokio-util::codec`.
*   [`src/errors.rs`](src/errors.rs): Defines custom error types for the application.
*   [`src/parsers.rs`](src/parsers.rs): Contains parsing logic for DNS packet components.
*   [`src/protocol.rs`](src/protocol.rs): Defines the data structures for DNS protocol elements (headers, questions, records).
*   [`src/response_builder.rs`](src/response_builder.rs): Implements the `DnsResponseBuilder` for constructing DNS responses.
*   [`src/actors/`](src/actors/): Contains actor-based components (e.g., `set_id_actor.rs`, `messages.rs`).
*   [`src/handlers/`](src/handlers/): Contains handlers for specific DNS operations (e.g., `set_id_handler.rs`).

## Dependencies

Key dependencies are managed via `Cargo.toml`:

*   `anyhow`: For flexible error handling.
*   `bytes`: Utilities for byte buffers.
*   `clap`: For parsing command-line arguments.
*   `futures`: Asynchronous stream utilities.
*   `hickory-resolver`: A DNS resolver library used for upstream lookups.
*   `nom`: A parser combinator library for robust parsing.
*   `thiserror`: For declarative error types.
*   `tokio`: An asynchronous runtime for building network applications.
*   `tokio-util`: Utilities for Tokio, including codecs.
*   `tracing`: For structured logging and diagnostics.
*   `tracing-subscriber`: A subscriber for `tracing` events.

## Testing

To run the comprehensive test suite for the project:

```bash
cargo test
```

Specifically for the `DnsResponseBuilder` tests:

```bash
cargo test response_builder
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.