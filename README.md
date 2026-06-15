# Glyph Hybrid Anchor Server

High-performance, hybrid (Bootstrap + Circuit Relay v2) decentralized server built in Rust for the Glyph P2P messaging client.

## 🚀 Features
- **QUIC & TCP Transports**: Dual listening on port `5678`.
- **Kademlia DHT**: Distributed name and peer resolution.
- **Circuit Relay v2**: Tunneling for NAT/firewall traversal.
- **Sled Storage**: Memory-mapped flash persistence for blind store-and-forward caching.
- **DCUtR**: Direct connection upgrade via hole punching.
- **Blind Push Webhooks**: Trigger Mobile App wake-up notifications.
- **Sybil Shield**: Connection rate limiting.
- **TTL Database Pruner**: Automatic database cache pruning.

## 🛠️ Requirements
- Rust stable (`cargo` / `rustc`)

## ⚙️ Configuration
The server identity is stored in a static key file `.glyph_identity` by default.
To run the server:
```bash
cargo run --release
```
