# Product Requirements Document (PRD): Glyph Hybrid Anchor Server

## 1. Executive Summary
The **Glyph Hybrid Anchor Server** is a decentralized routing, bootstrapping, and store-and-forward caching server. It provides the core networking backbone for the Glyph P2P messaging ecosystem. 

## 2. Core Pillars & Enterprise Layers
### 2.1 Zero-Metadata / Blind Networking
- The server must not know usernames, contents, or social graphs.
- Routing is based solely on cryptographic public key hashes and libp2p `PeerId`s.
- Offline message envelopes are cached under blind public key hashes.

### 2.2 Dual-Transport Layer
- **QUIC over UDP**: Primary transport for low-latency connection establishment and connection migration (switching between Wi-Fi and mobile networks).
- **TCP**: Fallback transport to guarantee delivery behind strict corporate firewalls.

### 2.3 Store-and-Forward Caching
- An embedded database (`Sled`) stores encrypted envelopes for offline peers.
- Envelopes are fetched immediately upon reconnection.

### 2.4 DCUtR (Direct Connection Upgrade through Relay)
- Matchmaking coordinator facilitating peer-to-peer hole-punching to offload server bandwidth.

### 2.5 Blind Push Webhook Trigger
- Ephemeral Device Push Tokens trigger post-gateway notifications when blind blobs are waiting.

### 2.6 Circuit Relay v2 Resource Reservation
- Restrict `max_reservations`, `max_circuits`, and `max_circuits_per_peer` to protect server capacity.

### 2.7 Sybil Shield (Connection Limits)
- Prevent connection/identity flooding attacks by limiting concurrent peer connections.

### 2.8 DB TTL Pruning
- Evict stale entries and expired envelopes after a TTL duration (e.g., 30 days) to keep routing tables fast.

## 3. Tech Stack
- **Language**: Rust (Latest stable)
- **Runtime**: Tokio (Multi-threaded)
- **Networking**: rust-libp2p v0.54
- **Database**: Sled (Embedded Key-Value database)
- **Concurrency**: DashMap (Sharded lock-free map)
- **Webhook client**: Reqwest/Tokio-based async webhook poster

## 4. Key Components
- **Kademlia DHT**: Identity routing.
- **Circuit Relay v2**: Connection proxying for NAT traversal.
- **DCUtR**: Direct connection negotiation.
- **Request-Response (CBOR)**: Envelope store-and-forward transport protocol.
- **Identify & Ping**: Peer metadata and connection liveness.
