# GLYPH HYBRID ANCHOR SERVER
## Complete Engineering Specification — v2.0
### Single-Document, All Sections, No Phases

---

# CONTENTS

```
§01  Executive Summary
§02  Formal Threat Model
§03  Zero-Metadata Guarantee — Formal Statement
§04  Data Taxonomy — What Is and Is Not Stored
§05  System Architecture
§06  Transport Layer
§07  Cryptographic Identity Layer
§08  Kademlia DHT Layer
§09  Circuit Relay v2 Layer
§10  DCUtR Layer
§11  Identify & Ping
§12  Request-Response Protocol (Wire Format)
§13  Blind Vault — Storage Engine
§14  Complete Event Loop
§15  Sybil Shield & Rate Limiting
§16  TTL Pruner
§17  Blind Push Webhook System
§18  Crash Resistance
§19  Performance Optimization
§20  Memory Safety
§21  Operational Security
§22  Non-Requirements
§23  Performance Targets
§24  Complete Dependency Manifest
§25  Complete Rust Type Definitions
§26  Formal Privacy Proof
```

---

# §01 EXECUTIVE SUMMARY

The **Glyph Hybrid Anchor Server** is a single Rust binary. It is a pure infrastructure node — not an application server, not a message broker, not a database of users.

Its three functions:

**1. Bootstrapping** — Mobile peers that have never met use the server to locate each other on the Kademlia DHT by their cryptographic PeerId.

**2. NAT Traversal** — When peers cannot connect directly (carrier NAT, symmetric NAT, corporate firewall), the server provides Circuit Relay v2 as a blind byte proxy and DCUtR as a hole-punch coordinator to attempt upgrading to a direct connection.

**3. Offline Delivery** — When the recipient is offline, an end-to-end encrypted envelope is held in the server's Blind Vault, keyed only by the hash of the recipient's public key. No sender information is stored. The ciphertext is opaque to the server.

The server is **structurally blind** — not by policy, but by data model. It is never given information it does not need, so it can never leak information it does not have.

---

# §02 FORMAL THREAT MODEL

### 2.1 Adversary Classification

| Class | Capability | Server Must Resist |
|---|---|---|
| Passive observer on server network link | Reads all packets to/from server | ✅ Noise XX encrypts all libp2p traffic |
| Active MITM | Injects, replays, modifies packets | ✅ Noise XX mutual auth, replay rejected by nonce |
| Sybil attacker | Floods with fake PeerIds | ✅ Connection limits, reservation limits, vault limits |
| Storage-access adversary | Full read of redb files on disk | ✅ All values are opaque ciphertexts; keys are SHA256 hashes |
| Process-memory adversary (root on running server) | Reads RAM | ✅ Secrets zeroized after use; no plaintext long-lived in heap |
| Legal compulsion (subpoena of server operator) | Demands logs and database | ✅ Logs contain no PII; database contains opaque hashes and ciphertexts |
| Timing correlation | Correlates store + fetch timing to link sender and recipient | ⚠️ Partial — store and fetch are unlinkable in data model; timing side-channel exists at network layer (out of scope without Tor on client) |
| Global passive adversary | Reads all backbone links | ❌ Out of scope — requires client-side Tor (Arti) integration |

### 2.2 What a Fully Compromised Server Exposes

Root access to the live running server yields:

```
DHT records:        { SHA256(pubkey) → Multiaddr }
                    → pseudonymous, no username, no real identity

Vault records:      { SHA256(pubkey) || seq → ciphertext }
                    → opaque blobs; no sender; no content

Active connections: [PeerId, ...] — pseudonymous identifiers only
Active circuits:    [(PeerId_A, PeerId_B, circuit_id)] — no content
Process memory:     Noise session keys (ephemeral, connection-scoped)
                    mimalloc heap (no persistent secrets; zeroized)
Logs:               Aggregate counts only; no PeerId, no IP in logs
```

**Conclusion:** A fully compromised server produces a set of cryptographic hashes mapping to encrypted blobs and transient network addresses. An adversary cannot read messages, identify users, or reconstruct who communicated with whom.

### 2.3 What Cannot Be Compromised By Any Server-Side Attack

- Message content (E2E encrypted sender-to-recipient, server has no key)
- Sender identity of any stored envelope (not stored)
- Social graph (not constructed, not stored)
- Username → PeerId mapping (not stored on server)
- Sender → recipient pairing for any in-flight or stored message

---

# §03 ZERO-METADATA GUARANTEE — FORMAL STATEMENT

Let:
- `A` = sender PeerId
- `B` = recipient PeerId  
- `m` = plaintext message
- `E_B(m)` = m encrypted with B's public key (E2E, sender-side)
- `H(x)` = SHA256(x)
- `Server` = this process with full disk and RAM access

**Guarantees:**

```
Server.stores(identity(A))                    = ⊥  (never stored)
Server.stores(identity(B))                    = ⊥  (never stored; H(pubkey(B)) stored, not B)
Server.stores(m)                              = ⊥  (never has plaintext)
Server.can_decrypt(E_B(m))                   = ⊥  (no decryption key)
Server.stores(social_link(A, B))             = ⊥  (not constructed)
Server.stores(IP(A) persistently)            = ⊥  (socket buffer only, never written)
Server.stores(IP(B) persistently)            = ⊥  (socket buffer only, never written)
Server.stores(username(A) ∨ username(B))     = ⊥  (never accepted as input)

Server.stores(H(pubkey(B)))                  = ✓  (vault key — pseudonymous)
Server.stores(E_B(m))                        = ✓  (opaque blob — server cannot read)
Server.stores(stored_at_timestamp)           = ✓  (TTL calculation only; not linked to A)
```

**This is a structural guarantee, not a configuration option.** The server's request handlers never accept sender identity as input. The vault schema has no sender field. Removing this guarantee would require rewriting the data model, not flipping a flag.

---

# §04 DATA TAXONOMY — WHAT IS AND IS NOT STORED

### 4.1 Accepted Inputs (What Enters the Server)

```
ACCEPTED — USED FOR ROUTING ONLY:
  PeerId                     In-memory for active connections; in DHT records
  Multiaddr (IP+port)        In DHT records only (peer's self-declared address)
  Encrypted vault payload    In redb vault table (opaque Vec<u8>)
  Recipient key hash         In redb vault key (32 bytes, SHA256 of pubkey)
  Blinded push token         In redb token table (encrypted, blinded)

ACCEPTED — IN-MEMORY ONLY, NEVER PERSISTED:
  Remote IP address          Socket fd, OS kernel; never read by application code
  Identify metadata          Protocol list, agent version; dropped after negotiation
  Noise session keys         Connection-scoped; dropped on disconnect
  Push token (raw)           Decrypted in memory for blinding; zeroized immediately after
```

### 4.2 Refused Inputs (What the Server Never Accepts)

```
REFUSED — NEVER ACCEPTED AS INPUT:
  Username or display name
  Sender identity in vault deposit
  Message plaintext
  Social relationship declarations
  Read receipts or delivery confirmations linking sender to recipient
  Device fingerprint or OS version
  App version beyond protocol negotiation
```

### 4.3 Emitted Outputs (What the Server Produces)

```
TO REQUESTING PEER:
  StoreAck { success: bool }              — confirmation, no metadata
  FetchResult { payloads: Vec<Vec<u8>> } — opaque ciphertexts, no metadata
  Error { code: u16 }                    — numeric code only, no text in production

TO LOGS:
  aggregate connection count (no peer IDs)
  aggregate vault entry count (no keys)
  aggregate bytes relayed (no circuit pairs)
  pruner run result (entry count delta only)
  fatal errors (no user-identifying data)
```

---

# §05 SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     GLYPH HYBRID ANCHOR NODE                           │
│                                                                         │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │  QUIC/UDP :5678  │    │   TCP :5678      │    │  IPv6 dual-stack │  │
│  │  (primary)       │    │   (fallback)     │    │  (both transports│  │
│  └────────┬─────────┘    └────────┬─────────┘    └──────────────────┘  │
│           │                       │                                     │
│           └───────────┬───────────┘                                     │
│                       │                                                 │
│              ┌────────▼────────┐                                        │
│              │   Noise XX      │ ← Mutual auth + E2E encryption        │
│              │   (Ed25519)     │   Rejects any unauth connection       │
│              └────────┬────────┘                                        │
│                       │                                                 │
│              ┌────────▼────────┐                                        │
│              │  Yamux Muxer   │ ← Multiplexes streams on one conn     │
│              │  (8MB window)  │   per-stream flow control             │
│              └────────┬────────┘                                        │
│                       │                                                 │
│  ┌────────────────────▼────────────────────────────────────────────┐   │
│  │                   SWARM EVENT LOOP                              │   │
│  │             (tokio::select! — non-blocking)                     │   │
│  └────────────────────┬────────────────────────────────────────────┘   │
│                       │                                                 │
│  ┌────────────────────▼────────────────────────────────────────────┐   │
│  │              GlyphAnchorBehaviour                               │   │
│  │                                                                 │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │   │
│  │  │  Kademlia   │  │ Relay Srv   │  │   DCUtR     │            │   │
│  │  │  DHT        │  │ v2          │  │   (punch)   │            │   │
│  │  │             │  │ (blind)     │  │             │            │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘            │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │   │
│  │  │  Request-   │  │  Identify   │  │    Ping     │            │   │
│  │  │  Response   │  │  (in-mem)   │  │  (liveness) │            │   │
│  │  │  (vault)    │  │             │  │             │            │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘            │   │
│  └────────────────────┬────────────────────────────────────────────┘   │
│                       │                                                 │
│  ┌────────────────────▼────────────────────────────────────────────┐   │
│  │              SHARED STATE (Arc-wrapped)                         │   │
│  │                                                                 │   │
│  │  ┌─────────────────────┐  ┌─────────────────────────────────┐  │   │
│  │  │  BLIND VAULT        │  │  SYBIL SHIELD                   │  │   │
│  │  │  redb Database      │  │  DashMap<IpAddr, ConnRecord>    │  │   │
│  │  │  SHA256(pk)→blob    │  │  DashMap<PeerId, RateRecord>    │  │   │
│  │  │  ACID, WAL, MVCC    │  │  DashMap<PeerId, PublicKey>     │  │   │
│  │  └─────────────────────┘  └─────────────────────────────────┘  │   │
│  └────────────────────┬────────────────────────────────────────────┘   │
│                       │                                                 │
│  ┌────────────────────▼────────────────────────────────────────────┐   │
│  │              BACKGROUND TASKS (tokio::spawn)                    │   │
│  │                                                                 │   │
│  │  ┌────────────────┐   ┌──────────────────┐   ┌──────────────┐  │   │
│  │  │  TTL Pruner    │   │  Webhook Engine  │   │  Metrics     │  │   │
│  │  │  hourly        │   │  HMAC-signed     │   │  5min emit   │  │   │
│  │  │  aggregate log │   │  3-attempt retry │   │  agg only    │  │   │
│  │  └────────────────┘   └──────────────────┘   └──────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Protocol Stack Per Connection

```
+──────────────────────────────────+  ← Application (Kad, Relay, RR, DCUtR)
│   Behaviour Event Dispatch       │
+──────────────────────────────────+  ← libp2p Swarm
│   Stream Multiplexing (Yamux)    │  window: 8MB, max streams: 512/conn
+──────────────────────────────────+  ← Security
│   Noise XX Handshake (Ed25519)   │  3-message, mutual auth, forward secrecy
+──────────────────────────────────+  ← Transport
│   QUIC-v1 (primary, UDP)         │  0-RTT on reconnect, path migration
│   TCP + Yamux (fallback)         │  guaranteed delivery, firewall-safe
+──────────────────────────────────+
│   DNS Resolver                   │  Multiaddr /dns4/ support
+──────────────────────────────────+
```

---

# §06 TRANSPORT LAYER

### 6.1 QUIC Configuration (Primary)

```rust
// libp2p QuicConfig
QuicConfig {
    support_draft_29: false,          // QUIC v1 only (RFC 9000)
    max_idle_timeout: 30_000,         // 30s (milliseconds)
    keep_alive_interval: 10_000,      // 10s keepalive to survive NAT timeouts
    max_concurrent_bidi_streams: 512, // per connection stream limit
    max_concurrent_uni_streams: 0,    // server does not use unidirectional
    send_window: 8 * 1024 * 1024,    // 8MB send window
    receive_window: 8 * 1024 * 1024, // 8MB receive window
}
```

**Why QUIC is primary:**
- **0-RTT reconnect**: Mobile clients switching Wi-Fi → 4G resume in 0 round-trips instead of TCP's 1.5 RTT for new connection + 1 RTT for TLS
- **Connection migration**: QUIC Connection ID persists across IP change; the connection survives network handoff without reconnect
- **HoL blocking**: QUIC streams are independent; a dropped packet in stream A does not stall stream B (unlike TCP + Yamux where a lost segment stalls the entire connection)
- **Built-in encryption**: QUIC mandates TLS 1.3 at the transport layer (supplemented by Noise at the libp2p layer)

### 6.2 TCP Configuration (Fallback)

TCP is the fallback for environments that block UDP (corporate firewalls, some ISPs, hotel networks).

```rust
TcpConfig {
    ttl: 64,
    nodelay: true,               // Disable Nagle — low-latency for small messages
    listen_backlog: 1024,        // OS listen queue depth
}
```

**TCP + Yamux window sizing:**
```rust
YamuxConfig {
    window_update_mode: WindowUpdateMode::OnRead,
    max_buffer_size: 16 * 1024 * 1024,  // 16MB buffer
    receive_window: 8 * 1024 * 1024,    // 8MB receive window per stream
    accept_backlog: 256,
}
```

### 6.3 Listening Addresses

```
/ip4/0.0.0.0/udp/5678/quic-v1
/ip4/0.0.0.0/tcp/5678
/ip6/::/udp/5678/quic-v1
/ip6/::/tcp/5678
```

Dual-stack (IPv4 + IPv6) on both transports. The server does not prefer one IP version over another.

### 6.4 Connection Limits

| Parameter | Value | Enforcement Layer |
|---|---|---|
| Max inbound connections (global) | 10,000 | libp2p ConnectionManager |
| Max connections per IP (IPv4 /32) | 20 | DashMap Sybil Shield |
| Max connections per IP (IPv6 /64 prefix) | 20 | DashMap Sybil Shield |
| Max new connections per IP per 60s | 30 | DashMap Sybil Shield |
| Connection idle timeout | 60s | QUIC idle_timeout / TCP keepalive |
| Max pending (half-open) connections | 256 | libp2p Transport config |
| Max simultaneous Noise handshakes | 512 | libp2p ConnectionManager |

On breach of per-IP limit: connection is **silently dropped** at transport layer before Noise handshake begins. No error response. Silent drop is mandatory — an error response leaks the existence of the rate limit threshold.

---

# §07 CRYPTOGRAPHIC IDENTITY LAYER

### 7.1 Ed25519 Keypair

The server's identity is an Ed25519 keypair. The PeerId is `multihash(compressed_ed25519_pubkey)` using the libp2p Identity multihash codec (for keys ≤ 42 bytes, the pubkey is embedded directly rather than hashed — this allows pubkey recovery from PeerId).

**Properties of Ed25519 for this use case:**
- Fast signature verification (AVX2 accelerated on x86_64)
- Small key size (32 bytes public, 64 bytes secret)
- Deterministic signatures (no random per-signature, eliminates nonce reuse attacks)
- Supported natively by libp2p Noise XX

### 7.2 Static Identity: `load_or_generate_keypair`

```rust
/// Path: .glyph_identity (or GLYPH_IDENTITY_PATH env var)
/// Format: 64 raw bytes — Ed25519 secret key scalar
/// Permissions: 0600 (enforced programmatically, server refuses to start if wrong)
fn load_or_generate_keypair(path: &Path) -> anyhow::Result<identity::Keypair> {
    if path.exists() {
        // Read exactly 64 bytes
        let bytes = fs::read(path)?;
        anyhow::ensure!(bytes.len() == 64, "Identity file corrupt: expected 64 bytes");
        let secret = identity::ed25519::SecretKey::try_from_bytes(
            bytes.try_into().unwrap()
        )?;
        Ok(identity::Keypair::from(identity::ed25519::Keypair::from(secret)))
    } else {
        // Generate fresh keypair
        let keypair = identity::Keypair::generate_ed25519();
        let ed25519 = keypair.as_ref()   // ed25519::Keypair
            .clone()
            .try_into_ed25519()?;
        let secret_bytes: [u8; 64] = ed25519.secret().as_ref().try_into()?;

        // ATOMIC WRITE: write to .tmp, then rename (POSIX rename is atomic)
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &secret_bytes)?;
        fs::set_permissions(&tmp_path, Permissions::from_mode(0o600))?;
        fs::rename(&tmp_path, path)?;  // atomic on Linux

        // Zeroize secret bytes from stack immediately
        secret_bytes.zeroize();

        tracing::info!(peer_id = %keypair.public().to_peer_id(), "Generated new identity");
        Ok(keypair)
    }
}
```

**Why atomic write matters:** If the process crashes while writing the identity file (power loss, OOM kill), an atomic rename guarantees either the old file or the new file exists — never a partial write that produces a corrupted 0–63 byte file that silently breaks PeerId derivation.

### 7.3 Startup Identity Validation

Before binding ports, the server must:
1. Verify identity file permissions are 0600 — refuse start if not (protects against world-readable key file)
2. Load keypair and derive PeerId
3. Log PeerId and all listen multiaddrs
4. Do not log the secret key bytes under any circumstances — including in error messages

### 7.4 Noise XX Handshake

Noise XX is the three-message pattern used for **mutual authentication**:

```
Initiator (Client)          Responder (Server)
─────────────────────────────────────────────
→ e                         (ephemeral pubkey)
← e, ee, s, es              (server's static key, shared secret mix)
→ s, se                     (client's static key, final shared secret)
─────────────────────────────────────────────
After: Both parties have:
  - Authenticated the other's static key
  - Established a symmetric session key with forward secrecy
  - Verified PeerId matches the declared key
```

**Result:** After Noise XX completes, each side has proof that the remote peer controls the private key corresponding to their declared PeerId. Any subsequent data is encrypted with a session key derived from ephemeral keys — forward secret even if static keys are later compromised.

---

# §08 KADEMLIA DHT LAYER

### 8.1 Purpose

The DHT provides global peer discovery. A client announces its current `Multiaddr` by storing a provider record under its PeerId. Other clients query the DHT with a PeerId to learn the current Multiaddr of that peer.

**Privacy boundary:** The DHT maps `PeerId → [Multiaddr]`. PeerId is a hash of a public key — pseudonymous. No username. No real identity. Equivalent metadata to what a DNS server holds: "this cryptographic identifier was reachable at this IP:port at this time."

### 8.2 Kademlia Configuration

```rust
let mut kad_config = kad::Config::new(
    StreamProtocol::new("/glyph/kad/1.0.0")  // MANDATORY custom name
);
kad_config
    .set_query_timeout(Duration::from_secs(60))
    .set_replication_factor(NonZeroUsize::new(3).unwrap())
    .set_record_ttl(Some(Duration::from_secs(86400)))       // 24h
    .set_publication_interval(Some(Duration::from_secs(43200)))  // 12h re-announce
    .set_connection_idle_timeout(Duration::from_secs(30))
    .set_kbucket_pending_timeout(Duration::from_secs(60))
    .set_max_packet_size(16 * 1024);  // 16KB max DHT message
```

**Why `/glyph/kad/1.0.0` is mandatory:** The default libp2p Kademlia protocol name is `/ipfs/kad/1.0.0`. Using it causes the server to interoperate with IPFS nodes — they will populate our DHT with IPFS routing records, our server will appear in IPFS routing tables, and the network boundary of the Glyph network becomes undefined. The custom protocol name creates a strict protocol boundary. Non-Glyph nodes cannot join or query the DHT.

### 8.3 DHT Record Validation

All `PUT_VALUE` records are signed by the storing peer's key. The server validates:
1. Record size ≤ 16 KB
2. Signature valid over (key, value, author, expiry)
3. Record expiry ≤ 24 hours from now
4. Author PeerId matches signature key

Records failing validation are silently dropped. No error response.

### 8.4 DHT Operation Rate Limits

| Operation | Limit | Window | Enforcement |
|---|---|---|---|
| `GET_VALUE` | 60 req | Per peer per 60s | DashMap RateRecord |
| `PUT_VALUE` | 10 req | Per peer per 60s | DashMap RateRecord |
| `FIND_NODE` | 30 req | Per peer per 60s | DashMap RateRecord |
| `ADD_PROVIDER` | 5 req | Per peer per 60s | DashMap RateRecord |
| `GET_PROVIDERS` | 20 req | Per peer per 60s | DashMap RateRecord |

Breach: operation silently dropped. No error code.

### 8.5 DHT Privacy Constraints

**Server MUST NOT log:**
- Content of any DHT record (Multiaddr of specific PeerId)
- Which PeerId queried for which target PeerId (query pair)
- Timing of DHT record insertions or retrievals

**Server MAY log (operational):**
- Total DHT routing table size (peer count only, no identities)
- Total DHT record count
- DHT query failure rate (aggregate %)

---

# §09 CIRCUIT RELAY v2 LAYER

### 9.1 Role

A blind byte forwarder. When Peer A cannot receive inbound connections (carrier NAT, no port forwarding), it makes a **reservation** on the relay server. Other peers then connect to A via the server. The server forwards encrypted bytes between A and the remote peer without reading them.

**The relay is completely opaque to the server.** It sees two PeerIds and a circuit ID. It sees byte counts. It sees nothing else.

### 9.2 Circuit Relay v2 Resource Configuration

```rust
relay::server::Config {
    max_reservations: 128,
    max_reservations_per_peer: 4,
    reservation_duration: Duration::from_secs(3600),        // 1h max reservation
    reservation_rate_limiters: vec![
        RelayRateLimiter::new_for_reservation(
            NonZeroU32::new(10).unwrap(),                   // 10 reservations/min global
            Duration::from_secs(60),
        ),
        RelayRateLimiter::new_for_reservation(
            NonZeroU32::new(4).unwrap(),                    // 4 reservations/min per peer
            Duration::from_secs(60),
        ),
    ],
    max_circuits: 256,
    max_circuits_per_peer: 8,
    max_circuit_duration: Duration::from_secs(1800),        // 30 min per circuit
    max_circuit_bytes: 100 * 1024 * 1024,                  // 100MB per circuit lifetime
    circuit_src_rate_limiters: vec![
        RelayRateLimiter::new_for_circuit(
            NonZeroU32::new(16).unwrap(),                   // 16 circuits/min global src
            Duration::from_secs(60),
        ),
        RelayRateLimiter::new_for_circuit(
            NonZeroU32::new(4).unwrap(),                    // 4 circuits/min per peer
            Duration::from_secs(60),
        ),
    ],
}
```

### 9.3 Relay v2 Protocol Flow

```
Client A (NAT, wants to receive)     Server           Client B (wants to reach A)
───────────────────────────────────────────────────────────────────────────────
A → Server: RESERVE
Server → A: RESERVATION_RESPONSE (reservation_id, expiry)

A advertises: /ip4/<server>/udp/5678/quic-v1/p2p/<server_id>/p2p-circuit/p2p/<A_id>

B → Server: CONNECT to <A_id>
Server → A: CONNECT notification (B's PeerId)
A → Server: ACK
Server ↔ A, Server ↔ B: bidirectional byte forwarding begins

[Both sides negotiate Noise XX over the circuit — server sees only encrypted bytes]
[DCUtR may now attempt hole punch to upgrade to direct connection]
```

### 9.4 Relay Privacy Enforcement

**MUST NOT log:**
- Circuit pair (PeerId_A, PeerId_B)
- Per-circuit byte counts
- Timestamps of circuit establishment
- Relay reservation owner and target

**MAY log:**
- Total active circuit count (integer, no identifiers)
- Total bytes forwarded (aggregate per 5-min interval)
- Reservation rejection count (rate limit hits, no peer IDs)

### 9.5 Relay as Last Resort

The server advertises relay capability but clients MUST attempt direct connection first. Relay traffic consumes server bandwidth. The client-side logic is:

```
1. Try direct QUIC connection to peer's Multiaddr → if success, done
2. If peer has relay reservation → open circuit
3. Over the circuit, run DCUtR to attempt hole punch
4. If DCUtR succeeds → upgrade to direct, close circuit
5. If DCUtR fails (symmetric NAT on both sides) → remain on relay
```

---

# §10 DCUtR LAYER

### 10.1 Purpose

DCUtR (Direct Connection Upgrade through Relay) runs over an existing relayed connection to attempt upgrading it to a direct P2P connection via NAT hole punching.

### 10.2 Protocol Sequence

```
     Client A (NAT-A)          Server (Relay)          Client B (NAT-B)
     ──────────────────────────────────────────────────────────────────
     [A and B already have a relayed connection through Server]

     A → B (via relay): CONNECT message with A's observed public address
     B → A (via relay): CONNECT message with B's observed public address
     
     [Synchronized countdown: both start simultaneous outbound connections]
     A → (NAT-A's public IP:port) → B
     B → (NAT-B's public IP:port) → A
     
     [If NAT-A and NAT-B are cone NATs: both inbound packets are accepted]
     [Direct connection established]
     [Relay circuit is closed]

     If both NATs are symmetric: hole punch fails, relay circuit persists
```

### 10.3 Server Role in DCUtR

The server's role is **passive signaling relay only** during DCUtR. It forwards the CONNECT messages between A and B over the existing circuit. It does not participate in the hole punch itself. It does not record the IP addresses that A and B exchange.

**Privacy note:** A and B necessarily exchange their public IP addresses during DCUtR (embedded in the CONNECT message). The server cannot prevent this — it is fundamental to hole punching. This is end-to-end encrypted over the Noise session, so the server's relay sees only opaque bytes.

The **privacy implication** is that after a successful DCUtR, both A and B know each other's public IP. For users who require IP-level anonymity, DCUtR must be disabled client-side and Tor used instead. This is a client architecture decision, not a server constraint.

---

# §11 IDENTIFY & PING

### 11.1 Identify Protocol

`identify::Behaviour` runs an exchange at the start of each connection where both peers declare:
- Their PeerId
- Their listen addresses
- Their agent version string
- The protocols they support

**Server policy:**
- **Receive** Identify from clients: store in `DashMap<PeerId, IdentifyInfo>` — in-memory only
- **Send** Identify to clients: declare server's PeerId, listen addresses, protocol list
- **Never persist** Identify data to disk
- **Drop** Identify records from DashMap on ConnectionClosed event
- **Use** the identify data to extract the client's PublicKey for vault key computation:
  ```rust
  // Extract public key from Identify info (more reliable than PeerId for non-Ed25519)
  peer_pubkeys.insert(peer_id, info.public_key.clone());
  ```

**Agent version string server sends:** `"glyph-anchor/0.2.0"` — no OS info, no build info.

### 11.2 Ping Protocol

`ping::Behaviour` sends a PING every 30 seconds. If no PONG within 10 seconds, the connection is considered dead and disconnected.

**Server policy:**
- Respond to pings: yes
- Initiate pings to peers: yes (server-initiated keeps idle connections alive through NATs)
- Log ping round-trip times: no
- Log ping failure events: no (connection will be dropped automatically by the behaviour)

---

# §12 REQUEST-RESPONSE PROTOCOL (WIRE FORMAT)

### 12.1 Protocol Identifier

```
/glyph/vault/1.0.0
```

Custom name mandatory — same reasoning as Kademlia. Non-Glyph nodes must not be able to participate in vault operations.

### 12.2 Serialization

**CBOR** (Concise Binary Object Representation) via `ciborium` crate.

| vs JSON | Rationale |
|---|---|
| 20–40% smaller binary payloads | Encrypted blobs are not compressible, but wrapper overhead matters |
| No UTF-8 encoding for binary fields | `Vec<u8>` encodes directly, no base64 |
| Schema-less, forward-compatible | New fields ignored by old receivers |
| Canonical encoding available | Consistent byte representation for signature verification |

### 12.3 Message Types (Complete)

```rust
#[derive(Debug, Serialize, Deserialize)]
pub enum GlyphRequest {
    /// Deposit an encrypted envelope for an offline recipient.
    /// Sender identity is NOT included — the server does not want it.
    Store {
        recipient_hash: [u8; 32],   // SHA256(recipient_pubkey_bytes)
        payload: Vec<u8>,           // E2E encrypted blob — opaque to server
    },

    /// Retrieve all pending envelopes for the authenticated caller.
    /// No parameters needed — identity is proved by the Noise XX connection.
    Fetch,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum GlyphResponse {
    /// Acknowledgement of a Store operation.
    StoreAck {
        success: bool,
        // Deliberately minimal — no envelope ID, no queue depth,
        // no timestamp, no confirmation of recipient existence.
    },

    /// Result of a Fetch operation.
    FetchResult {
        payloads: Vec<Vec<u8>>,
        // Raw encrypted blobs only.
        // No sender identity per blob.
        // No timestamp per blob.
        // No message ID per blob.
        // Delivered in stored_at order (oldest first).
    },

    /// Error response — numeric code only, no text in production builds.
    Error {
        code: u16,
    },
}
```

### 12.4 Error Codes

| Code | Meaning | Notes |
|---|---|---|
| 400 | Malformed request | Wrong field sizes, bad CBOR |
| 403 | Authentication failure | Fetch from unauthenticated peer |
| 413 | Payload too large | `payload.len() > MAX_ENVELOPE_SIZE` |
| 429 | Rate limit exceeded | Per-peer request limit |
| 507 | Vault full for recipient | `MAX_ENVELOPES_PER_RECIPIENT` reached |
| 500 | Internal server error | redb write failure, spawn_blocking panic |
| 503 | Server vault at capacity | Global `VAULT_CAPACITY_LIMIT` reached |

**In production:** `Error { code: 413 }` — no text. In debug builds: `Error { code: 413, debug_msg: "payload 68KB > 64KB limit" }` — debug only, never shipped.

### 12.5 Request-Response Codec

```rust
/// Codec implementing libp2p request_response::Codec
pub struct GlyphVaultCodec;

#[async_trait]
impl request_response::Codec for GlyphVaultCodec {
    type Protocol = StreamProtocol;
    type Request = GlyphRequest;
    type Response = GlyphResponse;

    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request> {
        // Read 4-byte length prefix (big-endian u32) then CBOR body
        // Max frame: 64KB + 1KB overhead = 65536 + 1024 bytes
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 66560 { return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large")); }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        ciborium::from_reader(buf.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()> {
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let len = (buf.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&buf).await?;
        io.flush().await
    }

    // read_response / write_response: symmetric, same length-prefix pattern
}
```

---

# §13 BLIND VAULT — STORAGE ENGINE

### 13.1 Why `redb`

The previous iteration specified `sled 0.34`. `sled` is **abandoned** (last release 2022, known data corruption under power loss, no async support, 0.x API unstable). It must not be used.

`redb 2.1` is the correct replacement:

| Property | sled 0.34 | redb 2.1 |
|---|---|---|
| Maintenance | ❌ Abandoned | ✅ Active development |
| ACID | Partial | ✅ Full MVCC + WAL |
| Crash safety | ❌ Known corruption | ✅ WAL guarantees atomicity |
| Async | ❌ Blocking only | ✅ MVCC read: lock-free; write: spawn_blocking |
| Pure Rust | ✅ | ✅ |
| API stability | 0.x frozen at broken | 2.x stable |
| Read performance | Good | ✅ Lock-free concurrent readers |
| Write performance | OK | ✅ Batch writes in single transaction |

### 13.2 Table Schema

```rust
// Vault table: one entry per envelope
// Key: [32 bytes SHA256(pubkey)] ++ [8 bytes big-endian monotonic timestamp ns]
// Value: CBOR-encoded VaultEntry
const VAULT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("vault_v1");

// Token table: blinded push tokens
// Key: 32 bytes SHA256(pubkey)  (same key as vault)
// Value: CBOR-encoded BlindedToken
const TOKENS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("tokens_v1");

// Sequence counter table (per recipient, for ordering)
// Key: 32 bytes SHA256(pubkey)
// Value: u64 big-endian next sequence number
const SEQNO: TableDefinition<&[u8], u64> =
    TableDefinition::new("seqno_v1");

/// Stored with each vault entry (value side)
#[derive(Serialize, Deserialize)]
pub struct VaultEntry {
    pub stored_at: u64,    // Unix seconds — for TTL only
    pub payload: Vec<u8>,  // Encrypted blob — opaque to server
    // NO sender_peer_id
    // NO sender_pubkey
    // NO message_type
    // NO metadata of any kind
}
```

### 13.3 Composite Key Design

A single recipient may have multiple pending envelopes. The composite key places them in adjacent byte ranges:

```
Key layout (40 bytes total):
  [0..32]  = SHA256(recipient_pubkey)     — constant for all envelopes of one recipient
  [32..40] = sequence_number (u64, BE)    — monotonically increasing per recipient

Example:
  Key_0 = [3a4f...e7 | 0000000000000001]  ← oldest envelope
  Key_1 = [3a4f...e7 | 0000000000000002]
  Key_2 = [3a4f...e7 | 0000000000000003]  ← newest envelope

Range scan to fetch all: scan keys where key[0..32] == recipient_hash
This is a single redb range scan — O(n) where n = envelope count for that recipient.
```

**Sequence number management:** stored in the `SEQNO` table. On each Store, atomically read-increment-write within the same redb write transaction. On each Fetch+Delete, reset SEQNO to 0 for that recipient within the same transaction as the deletions. This is a single ACID transaction — no partial state possible.

### 13.4 Store Operation

```rust
pub async fn vault_store(
    db: Arc<Database>,
    recipient_hash: [u8; 32],
    payload: Vec<u8>,
    rate_state: Arc<SybilShield>,
    webhook_tx: UnboundedSender<WebhookTask>,
) -> Result<GlyphResponse, anyhow::Error> {
    // 1. Input validation (before touching DB)
    if recipient_hash.len() != 32 {
        return Ok(GlyphResponse::Error { code: 400 });
    }
    if payload.len() > MAX_ENVELOPE_SIZE {           // 64 * 1024
        return Ok(GlyphResponse::Error { code: 413 });
    }

    // 2. All DB ops in spawn_blocking (redb write transactions are sync)
    let response = tokio::task::spawn_blocking(move || {
        let write_txn = db.begin_write()?;
        {
            let mut vault = write_txn.open_table(VAULT)?;
            let mut seqno_table = write_txn.open_table(SEQNO)?;

            // Read current count for recipient (prefix scan)
            let prefix_start: [u8; 40] = {
                let mut k = [0u8; 40];
                k[..32].copy_from_slice(&recipient_hash);
                k
            };
            let prefix_end: [u8; 40] = {
                let mut k = [0xff_u8; 40];
                k[..32].copy_from_slice(&recipient_hash);
                k
            };
            let count = vault.range(prefix_start.as_ref()..=prefix_end.as_ref())?.count();
            if count >= MAX_ENVELOPES_PER_RECIPIENT {  // 500
                return Ok(GlyphResponse::Error { code: 507 });
            }

            // Get and increment sequence number
            let seq = seqno_table
                .get(recipient_hash.as_ref())?
                .map(|v| v.value())
                .unwrap_or(0);
            let next_seq = seq + 1;
            seqno_table.insert(recipient_hash.as_ref(), next_seq)?;

            // Build composite key
            let mut key = [0u8; 40];
            key[..32].copy_from_slice(&recipient_hash);
            key[32..].copy_from_slice(&next_seq.to_be_bytes());

            // Serialize entry (no sender, no metadata)
            let entry = VaultEntry {
                stored_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                payload,
            };
            let mut entry_bytes = Vec::new();
            ciborium::into_writer(&entry, &mut entry_bytes)?;

            vault.insert(key.as_ref(), entry_bytes.as_ref())?;
        }
        write_txn.commit()?;
        anyhow::Ok(GlyphResponse::StoreAck { success: true })
    }).await??;

    // 3. Trigger webhook notification (non-blocking, best-effort)
    let _ = webhook_tx.send(WebhookTask { recipient_hash });

    Ok(response)
}
```

### 13.5 Fetch Operation (Authenticated by Noise Layer)

```rust
pub async fn vault_fetch(
    db: Arc<Database>,
    requesting_peer_pubkey: identity::PublicKey,  // Extracted from Noise / Identify
) -> Result<GlyphResponse, anyhow::Error> {
    // Derive recipient_hash from the authenticated peer's public key
    // This is the ONLY valid authentication — the peer can only fetch their own envelopes
    let pubkey_bytes = requesting_peer_pubkey.encode_protobuf();
    let recipient_hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(&pubkey_bytes);
        hasher.finalize().into()
    };

    let payloads = tokio::task::spawn_blocking(move || {
        let write_txn = db.begin_write()?;  // Write txn because we delete after read
        let payloads: Vec<Vec<u8>> = {
            let mut vault = write_txn.open_table(VAULT)?;
            let mut seqno_table = write_txn.open_table(SEQNO)?;

            let prefix_start: [u8; 40] = { let mut k = [0u8; 40]; k[..32].copy_from_slice(&recipient_hash); k };
            let prefix_end: [u8; 40] = { let mut k = [0xff_u8; 40]; k[..32].copy_from_slice(&recipient_hash); k };

            // Collect all entries (payload bytes only — strip metadata)
            let mut results = Vec::new();
            let mut keys_to_delete = Vec::new();
            for item in vault.range(prefix_start.as_ref()..=prefix_end.as_ref())? {
                let (k, v) = item?;
                let entry: VaultEntry = ciborium::from_reader(v.value())?;
                results.push(entry.payload);
                keys_to_delete.push(k.value().to_vec());
            }

            // Atomically delete all fetched entries + reset seqno
            for key in &keys_to_delete {
                vault.remove(key.as_ref())?;
            }
            if !keys_to_delete.is_empty() {
                seqno_table.insert(recipient_hash.as_ref(), 0u64)?;
            }

            results
        };
        write_txn.commit()?;
        anyhow::Ok(payloads)
    }).await??;

    // Return payloads — no metadata, no sender info, no timestamps
    Ok(GlyphResponse::FetchResult { payloads })
}
```

**Critical:** Fetch and Delete are a single ACID transaction. If the connection drops after the fetch but before the delete, the payload is gone and the client must resend. This is acceptable for the threat model — it is better to lose an envelope than to create a situation where envelopes are retained after supposed delivery (which would be a data minimization violation).

An alternative is to keep the envelope and add a `delivered: bool` flag — but this requires storing a second field and creates the possibility of indefinite retention. Atomic delete-on-fetch is the correct zero-retention design.

### 13.6 Vault Operational Limits

| Parameter | Value | Notes |
|---|---|---|
| `MAX_ENVELOPE_SIZE` | 64 KB | Typical E2E message < 1KB; 64KB allows file metadata |
| `MAX_ENVELOPES_PER_RECIPIENT` | 500 | Prevents single recipient consuming vault |
| `VAULT_CAPACITY_LIMIT` | 50 GB | Total redb file size check before accepting Store |
| `DEFAULT_TTL` | 30 days | Non-negotiable; enforced by pruner |
| `MIN_PAYLOAD_SIZE` | 32 bytes | Reject trivially small payloads (likely probes) |

---

# §14 COMPLETE EVENT LOOP

### 14.1 Main Loop Structure

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // [Setup: logging, keypair, swarm, DB, state — see §24]
    
    let mut pruner_ticker = tokio::time::interval(Duration::from_secs(3600));
    let mut metrics_ticker = tokio::time::interval(Duration::from_secs(300));
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::unbounded_channel::<WebhookTask>();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    
    // Spawn background tasks
    tokio::spawn(webhook_engine(webhook_rx, db.clone(), shutdown_tx.subscribe()));
    
    // Install SIGTERM + SIGINT handlers
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            // ── Primary: swarm events ──────────────────────────────────────
            event = swarm.next() => {
                let Some(event) = event else { break };
                handle_swarm_event(
                    event, &mut swarm,
                    &db, &shield, &peer_pubkeys, &webhook_tx
                ).await?;
            }

            // ── Hourly: TTL pruner ─────────────────────────────────────────
            _ = pruner_ticker.tick() => {
                let db2 = db.clone();
                tokio::task::spawn_blocking(move || prune_vault(&db2));
            }

            // ── 5-min: aggregate metrics ───────────────────────────────────
            _ = metrics_ticker.tick() => {
                emit_metrics(&swarm, &db, &shield);
            }

            // ── Graceful shutdown ──────────────────────────────────────────
            _ = &mut ctrl_c => {
                tracing::info!("Shutdown signal received. Draining connections...");
                let _ = shutdown_tx.send(());
                break;
            }
        }
    }

    Ok(())
}
```

### 14.2 SwarmEvent Handler — All Variants

```rust
async fn handle_swarm_event(
    event: SwarmEvent<GlyphAnchorEvent>,
    swarm: &mut Swarm<GlyphAnchorBehaviour>,
    db: &Arc<Database>,
    shield: &Arc<SybilShield>,
    peer_pubkeys: &Arc<DashMap<PeerId, identity::PublicKey>>,
    webhook_tx: &UnboundedSender<WebhookTask>,
) -> anyhow::Result<()> {
    match event {
        // ── Behaviour Events ───────────────────────────────────────────────
        SwarmEvent::Behaviour(ev) => {
            handle_behaviour_event(ev, swarm, db, shield, peer_pubkeys, webhook_tx).await?
        }

        // ── Connection Established ─────────────────────────────────────────
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            // Sybil Shield: check and register connection
            // Note: endpoint.get_remote_address() gives Multiaddr (IP+port)
            // We ONLY use this for per-IP connection limiting — never log it
            if let Some(ip) = extract_ip(&endpoint) {
                match shield.check_and_register_connection(ip) {
                    ConnectionVerdict::Allow => {
                        // Proceed — connection is active
                        // Do NOT log peer_id or IP
                    }
                    ConnectionVerdict::Deny => {
                        // Exceeded per-IP limit — close connection
                        swarm.disconnect_peer_id(peer_id).ok();
                    }
                }
            }
        }

        // ── Connection Closed ──────────────────────────────────────────────
        SwarmEvent::ConnectionClosed { peer_id, endpoint, .. } => {
            // Deregister from IP connection count
            if let Some(ip) = extract_ip(&endpoint) {
                shield.deregister_connection(ip);
            }
            // Remove cached pubkey to avoid memory growth
            peer_pubkeys.remove(&peer_id);
            // No logging of peer_id
        }

        // ── New Listen Address ─────────────────────────────────────────────
        SwarmEvent::NewListenAddr { address, .. } => {
            // This IS safe to log — it's the server's own address
            tracing::info!(addr = %address, "Listening");
            // Add to Kademlia's external addresses
            swarm.add_external_address(address);
        }

        // ── Incoming Connection (pre-Noise) ───────────────────────────────
        SwarmEvent::IncomingConnection { .. } => {
            // Do not log: would create a record of incoming IP
        }

        // ── Connection Errors ──────────────────────────────────────────────
        SwarmEvent::IncomingConnectionError { error, .. } => {
            // Log the error TYPE only — not remote address
            tracing::debug!(err = %error.to_string().split(':').next().unwrap_or("unknown"), "Incoming conn error");
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            // Server rarely initiates outgoing — log for debug only
            tracing::debug!(err = %error, "Outgoing conn error");
        }

        // ── Address Confirmed ─────────────────────────────────────────────
        SwarmEvent::ExternalAddrConfirmed { address } => {
            tracing::info!(addr = %address, "External address confirmed");
        }

        // ── Address Expired ────────────────────────────────────────────────
        SwarmEvent::ExternalAddrExpired { address } => {
            tracing::info!(addr = %address, "External address expired");
        }

        _ => {} // Catch future variants without crashing
    }

    Ok(())
}
```

### 14.3 Behaviour Event Handler — All Variants

```rust
async fn handle_behaviour_event(
    event: GlyphAnchorEvent,
    swarm: &mut Swarm<GlyphAnchorBehaviour>,
    db: &Arc<Database>,
    shield: &Arc<SybilShield>,
    peer_pubkeys: &Arc<DashMap<PeerId, identity::PublicKey>>,
    webhook_tx: &UnboundedSender<WebhookTask>,
) -> anyhow::Result<()> {
    match event {
        // ── Kademlia ───────────────────────────────────────────────────────
        GlyphAnchorEvent::Kad(kad_event) => match kad_event {
            kad::Event::InboundRequest { request } => {
                // Validate and rate-limit
                // Most validation is handled by kad::Behaviour internally
                // (record size, signature, TTL)
                // We only add rate limiting on top
                // (peer identity available via in-flight connection context)
                drop(request); // Processed by behaviour — we observe only
            }
            kad::Event::RoutingUpdated { .. } => { /* Normal DHT churn */ }
            kad::Event::OutboundQueryProgressed { .. } => { /* Server rarely queries */ }
            kad::Event::UnroutablePeer { .. } => { /* Peer disappeared from DHT */ }
            _ => {}
        },

        // ── Relay Server ───────────────────────────────────────────────────
        GlyphAnchorEvent::Relay(relay_event) => match relay_event {
            relay::server::Event::ReservationReqAccepted { .. } => {
                // No logging — would record peer identity
            }
            relay::server::Event::ReservationReqDenied { .. } => {
                // Count aggregate denials only
                shield.increment_relay_denial();
            }
            relay::server::Event::CircuitReqAccepted { .. } => {
                // No logging — would record circuit pair
            }
            relay::server::Event::CircuitReqDenied { .. } => {
                shield.increment_circuit_denial();
            }
            relay::server::Event::CircuitClosed { .. } => {
                // No logging — no circuit identifiers
            }
            _ => {}
        },

        // ── Request-Response (Vault Protocol) ─────────────────────────────
        GlyphAnchorEvent::RequestResponse(rr_event) => match rr_event {
            request_response::Event::Message { peer, message } => match message {
                request_response::Message::Request { request, channel, .. } => {
                    // Check per-peer rate limit before processing
                    if !shield.check_vault_ratelimit(&peer) {
                        let _ = swarm.behaviour_mut().request_response
                            .send_response(channel, GlyphResponse::Error { code: 429 });
                        return Ok(());
                    }

                    let response = match request {
                        GlyphRequest::Store { recipient_hash, payload } => {
                            vault_store(
                                db.clone(),
                                recipient_hash,
                                payload,
                                shield.clone(),
                                webhook_tx.clone(),
                            ).await.unwrap_or(GlyphResponse::Error { code: 500 })
                        }

                        GlyphRequest::Fetch => {
                            // Authenticate via cached public key from Identify
                            if let Some(pubkey) = peer_pubkeys.get(&peer) {
                                vault_fetch(db.clone(), pubkey.clone())
                                    .await
                                    .unwrap_or(GlyphResponse::Error { code: 500 })
                            } else {
                                // Public key not yet known — Identify hasn't completed
                                GlyphResponse::Error { code: 403 }
                            }
                        }
                    };

                    let _ = swarm.behaviour_mut().request_response
                        .send_response(channel, response);
                }

                request_response::Message::Response { .. } => {
                    // Server does not initiate requests — this is unexpected
                    tracing::warn!("Unexpected Response message from peer (server is responder only)");
                }
            },

            request_response::Event::InboundFailure { error, .. } => {
                // Log error type only, no peer identity
                tracing::debug!(err = ?error, "Vault inbound failure");
            }
            request_response::Event::OutboundFailure { error, .. } => {
                tracing::debug!(err = ?error, "Vault outbound failure");
            }
            request_response::Event::ResponseSent { .. } => {
                // No logging — would count responses per peer
            }
        },

        // ── DCUtR ──────────────────────────────────────────────────────────
        GlyphAnchorEvent::Dcutr(dcutr_event) => match dcutr_event {
            dcutr::Event::InitiatedDirectConnectionUpgrade { .. } => {
                // No action required — DCUtR runs over the relay connection
                // Server is passive here
            }
            dcutr::Event::RemoteInitiatedDirectConnectionUpgrade { .. } => {}
            dcutr::Event::DirectConnectionUpgradeSucceeded { .. } => {
                // Upgrade complete — relay circuit will be closed by libp2p
                // No logging — would record connection pair
            }
            dcutr::Event::DirectConnectionUpgradeFailed { .. } => {
                // Hole punch failed — relay circuit persists
                // No logging — would record peer identity
            }
        },

        // ── Identify ──────────────────────────────────────────────────────
        GlyphAnchorEvent::Identify(identify_event) => match identify_event {
            identify::Event::Received { peer_id, info, .. } => {
                // Store public key for vault fetch authentication
                peer_pubkeys.insert(peer_id, info.public_key.clone());

                // Add observed addresses to Kademlia for routing
                for addr in info.listen_addrs {
                    swarm.behaviour_mut().kad
                        .add_address(&peer_id, addr);
                }
                // No logging of peer_id or addresses
            }
            identify::Event::Sent { .. } => {}
            identify::Event::Pushed { .. } => {}
            identify::Event::Error { error, .. } => {
                tracing::debug!(err = %error, "Identify error");
            }
        },

        // ── Ping ──────────────────────────────────────────────────────────
        GlyphAnchorEvent::Ping(ping_event) => match ping_event {
            ping::Event { result: Ok(_), .. } => {
                // Peer is alive — no action, no logging
            }
            ping::Event { result: Err(e), .. } => {
                // Connection health failure — libp2p will disconnect automatically
                tracing::debug!(err = %e, "Ping failure (peer will be disconnected)");
            }
        },
    }

    Ok(())
}
```

---

# §15 SYBIL SHIELD & RATE LIMITING

### 15.1 Shared State Structure

```rust
pub struct SybilShield {
    // Per-IP connection tracking
    ip_connections: DashMap<IpAddr, IpRecord>,

    // Per-PeerId vault operation rate limiting
    peer_vault_ops: DashMap<PeerId, VaultRateRecord>,

    // Per-PeerId DHT operation rate limiting
    peer_dht_ops: DashMap<PeerId, DhtRateRecord>,

    // Aggregate counters for metrics (no per-peer info)
    relay_denials: AtomicU64,
    circuit_denials: AtomicU64,
    vault_rejections: AtomicU64,
    dht_rejections: AtomicU64,
}

#[derive(Default)]
struct IpRecord {
    active_connections: AtomicU32,
    connections_last_window: AtomicU32,
    window_start: Mutex<Instant>,
}

#[derive(Default)]
struct VaultRateRecord {
    store_ops: AtomicU32,
    fetch_ops: AtomicU32,
    window_start: Mutex<Instant>,
}
```

### 15.2 Connection Verdict

```rust
pub enum ConnectionVerdict { Allow, Deny }

impl SybilShield {
    pub fn check_and_register_connection(&self, ip: IpAddr) -> ConnectionVerdict {
        let record = self.ip_connections.entry(ip).or_default();

        // Check active connection limit
        let active = record.active_connections.load(Ordering::Relaxed);
        if active >= MAX_CONNECTIONS_PER_IP { // 20
            return ConnectionVerdict::Deny;
        }

        // Check rate (connections per 60s window)
        let mut window_start = record.window_start.lock().unwrap();
        if window_start.elapsed() >= Duration::from_secs(60) {
            record.connections_last_window.store(0, Ordering::Relaxed);
            *window_start = Instant::now();
        }
        let rate = record.connections_last_window.fetch_add(1, Ordering::Relaxed);
        if rate >= MAX_NEW_CONNECTIONS_PER_IP_PER_MINUTE { // 30
            return ConnectionVerdict::Deny;
        }

        record.active_connections.fetch_add(1, Ordering::Relaxed);
        ConnectionVerdict::Allow
    }

    pub fn deregister_connection(&self, ip: IpAddr) {
        if let Some(record) = self.ip_connections.get(&ip) {
            record.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn check_vault_ratelimit(&self, peer: &PeerId) -> bool {
        let record = self.peer_vault_ops.entry(*peer).or_default();
        let mut window_start = record.window_start.lock().unwrap();
        if window_start.elapsed() >= Duration::from_secs(60) {
            record.store_ops.store(0, Ordering::Relaxed);
            record.fetch_ops.store(0, Ordering::Relaxed);
            *window_start = Instant::now();
        }
        // Combined vault ops limit
        let total = record.store_ops.load(Ordering::Relaxed)
            + record.fetch_ops.load(Ordering::Relaxed);
        if total >= MAX_VAULT_OPS_PER_PEER_PER_MINUTE { // 15
            self.vault_rejections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }
}
```

### 15.3 IPv6 Grouping

IPv6 clients have huge address spaces and can trivially rotate /128 addresses. Rate limiting must be applied at the /64 prefix level:

```rust
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            // Zero out the host portion (last 8 bytes of 16-byte IPv6)
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}
```

### 15.4 DashMap Memory Bounds

DashMap entries for disconnected peers accumulate without cleanup. Bound the map sizes:

```rust
// Periodic cleanup: remove stale IP records (no active connections, window expired)
// Called every 10 minutes from the event loop ticker
fn cleanup_shield(shield: &SybilShield) {
    shield.ip_connections.retain(|_, record| {
        record.active_connections.load(Ordering::Relaxed) > 0
            || record.window_start.lock().unwrap().elapsed() < Duration::from_secs(300)
    });
    shield.peer_vault_ops.retain(|_, record| {
        record.window_start.lock().unwrap().elapsed() < Duration::from_secs(300)
    });
}
```

### 15.5 Rate Limit Summary

| Scope | Metric | Limit | Window |
|---|---|---|---|
| Per IPv4 address | Active connections | 20 | — |
| Per IPv6 /64 prefix | Active connections | 20 | — |
| Per IP | New connections | 30 | 60s |
| Per PeerId | Vault ops (store + fetch total) | 15 | 60s |
| Per PeerId | DHT GET ops | 60 | 60s |
| Per PeerId | DHT PUT ops | 10 | 60s |
| Per PeerId | Relay reservations | 4 | 60s |
| Per PeerId | Circuit initiations | 4 | 60s |
| Global | Max active connections | 10,000 | — |
| Global | Max relay circuits | 256 | — |
| Global | Max relay reservations | 128 | — |

---

# §16 TTL PRUNER

### 16.1 Design

Background `tokio::spawn_blocking` task. Runs hourly. No interference with vault R/W operations (redb MVCC — readers never block writers, writers never block readers).

```rust
async fn start_pruner(db: Arc<Database>, mut shutdown: broadcast::Receiver<()>) {
    // Random startup delay 0-600s to avoid synchronized storms across instances
    let jitter = rand::random::<u64>() % 600;
    tokio::time::sleep(Duration::from_secs(jitter)).await;

    let mut interval = tokio::time::interval(Duration::from_secs(3600));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let db2 = db.clone();
                let pruned = tokio::task::spawn_blocking(move || prune_vault_sync(&db2))
                    .await
                    .unwrap_or(Ok(0))
                    .unwrap_or(0);
                // ONLY aggregate count — no keys, no hashes
                tracing::info!(pruned_count = pruned, "TTL prune complete");
            }
            _ = shutdown.recv() => {
                tracing::info!("Pruner shutting down");
                break;
            }
        }
    }
}

fn prune_vault_sync(db: &Database) -> anyhow::Result<u64> {
    let cutoff = SystemTime::now()
        .duration_since(UNIX_EPOCH)?.as_secs()
        .saturating_sub(TTL_SECONDS);  // 30 * 24 * 3600 = 2_592_000

    let write_txn = db.begin_write()?;
    let mut pruned: u64 = 0;
    {
        let mut vault = write_txn.open_table(VAULT)?;
        let expired_keys: Vec<Vec<u8>> = vault.iter()?
            .filter_map(|item| {
                let (k, v) = item.ok()?;
                let entry: VaultEntry = ciborium::from_reader(v.value()).ok()?;
                if entry.stored_at < cutoff {
                    Some(k.value().to_vec())
                } else {
                    None
                }
            })
            .collect();
        for key in &expired_keys {
            vault.remove(key.as_ref())?;
            pruned += 1;
        }
    }
    write_txn.commit()?;
    Ok(pruned)
}
```

### 16.2 Pruner Privacy Invariant

The pruner iterates over ALL vault keys. The only information it logs is the count of pruned entries. At no point does it:
- Log any key (which would reveal that a specific hash had pending messages)
- Log stored_at timestamps
- Log payload sizes per entry

---

# §17 BLIND PUSH WEBHOOK SYSTEM

### 17.1 Privacy Problem

Push notification tokens (APNs, FCM) are device identifiers. If the server stores `SHA256(pubkey) → push_token` in plaintext, it creates a link from a cryptographic identity to a device ID. A subpoena of the server could then reveal which device is associated with which cryptographic identity.

### 17.2 Blind Token Architecture

The push token is encrypted before storage. The storage key is a blind hash. The raw token is never persisted.

```
Client-side:
1. Client encrypts push_token with server's Ed25519 pubkey (ECIES)
2. Client sends RegisterToken { recipient_hash, encrypted_token, expiry }

Server-side:
3. Decrypt push_token in memory using server's private key
4. blind_key = SHA256(push_token || server_secret_32bytes)
5. stored_value = AES-256-GCM(push_token, server_secret)  [or ChaCha20-Poly1305]
6. Write (blind_key → stored_value) to TOKENS table
7. Zeroize push_token bytes from memory
8. Store blind_key in memory as the lookup index for recipient_hash:
   token_index.insert(recipient_hash, blind_key)
```

**Result:** The TOKENS redb table maps opaque 32-byte blind keys to AES-GCM encrypted token blobs. Without the server's secret, neither the blind key nor the stored value reveals the push token or the cryptographic identity it belongs to.

### 17.3 Webhook Delivery

```rust
async fn send_webhook(
    raw_token: Vec<u8>,  // decrypted from TOKENS table
    webhook_url: &str,
    server_secret: &[u8; 32],
    http_client: &reqwest::Client,
) {
    // Minimal payload — no content, no sender, no metadata
    let payload = serde_json::json!({
        "token": base64::encode(&raw_token),
        "notification": {} // Empty body — just wake up the device
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // HMAC-SHA256 signature over the request body
    let mut mac = Hmac::<Sha256>::new_from_slice(server_secret).unwrap();
    mac.update(&payload_bytes);
    let signature = hex::encode(mac.finalize().into_bytes());

    // Retry logic: 3 attempts with exponential backoff
    for attempt in 0..3u32 {
        let delay = Duration::from_secs(5u64.pow(attempt));
        if attempt > 0 { tokio::time::sleep(delay).await; }

        let result = http_client
            .post(webhook_url)
            .header("Content-Type", "application/json")
            .header("X-Glyph-Signature", &signature)
            .body(payload_bytes.clone())
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match result {
            Ok(r) if r.status().is_success() => return,
            Ok(r) => tracing::debug!(status = r.status().as_u16(), attempt, "Webhook non-2xx"),
            Err(e) => tracing::debug!(err = %e, attempt, "Webhook send error"),
        }
    }
    // Log aggregate failure — no token, no recipient hash
    tracing::warn!("Webhook delivery failed after 3 attempts");
}
```

### 17.4 Token Registration Protocol

```rust
// Added to GlyphRequest enum
RegisterToken {
    recipient_hash: [u8; 32],           // SHA256(pubkey)
    encrypted_token: Vec<u8>,           // ECIES-encrypted push token
    expiry: u64,                        // Unix timestamp (token expiry from APNs/FCM)
},
```

Tokens are single-use or expiry-bound. On delivery attempt, the token entry is deleted from TOKENS table regardless of delivery success (best-effort delivery; on next reconnect the client re-registers a fresh token).

---

# §18 CRASH RESISTANCE

### 18.1 redb Transaction Safety

redb uses a **Write-Ahead Log (WAL)**. Every committed transaction is durable before `commit()` returns. On crash:
- **Before `commit()`**: Transaction is rolled back entirely on next open. No partial state.
- **After `commit()`**: Changes are durable. No data loss.
- **During WAL write**: redb's WAL journal is applied on next `Database::open()`.

The store operation (§13.4) commits a single write transaction containing both the vault entry and the seqno update. They commit atomically or not at all.

### 18.2 Keypair File Atomic Write

See §7.2. The `write → rename` pattern on Linux is POSIX-guaranteed atomic. There is no moment in time where the identity file contains partial bytes.

### 18.3 panic = "abort"

```toml
[profile.release]
panic = "abort"
```

**Why `"abort"` not `"unwind"`:**
- `"unwind"` attempts stack unwinding on panic. During unwinding, `Drop` implementations run. For a network server under load, unwinding concurrent tasks leads to partially-dropped state: open file descriptors, locked mutexes that never unlock, half-written vault entries (if not using transactions properly).
- `"abort"` kills the process immediately. The OS reclaims all resources atomically. redb's WAL ensures the DB is consistent on next open. systemd restarts the process in < 1 second.
- `strip = true` makes unwind metadata in the binary useless anyway — stack traces are not readable from a stripped binary.

**Implication:** Every code path must use `?` and `anyhow::Result`. `unwrap()` on `None` or `Err` becomes a process abort. This is acceptable — the server has no persistent in-memory state that cannot be reconstructed from redb on restart. Active relay circuits are lost (clients reconnect). DHT routing table is rebuilt by reconnecting peers (< 60 seconds). Vault is intact.

### 18.4 No `unwrap()` in Hot Paths

Acceptable `unwrap()` uses (programmer error, can never actually fail):
- `NonZeroUsize::new(3).unwrap()` — literal 3 is always non-zero
- `key[..32].try_into().unwrap()` — known-size slice

Unacceptable (must use `?`):
- Any I/O operation
- Any parse operation on external data
- Any lock acquisition (`mutex.lock()` — should use `unwrap()` only if poisoning is impossible)
- Any redb operation
- Any channel send where the receiver may have dropped

### 18.5 Systemd Service Hardening

```ini
[Unit]
Description=Glyph Hybrid Anchor Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=glyph-server
Group=glyph-server
ExecStart=/usr/local/bin/glyph-anchor-server
Restart=always
RestartSec=1s
StartLimitIntervalSec=60s
StartLimitBurst=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RemoveIPC=true
CapabilityBoundingSet=
AmbientCapabilities=

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Working directory for identity file and DB
WorkingDirectory=/var/lib/glyph-anchor
ReadWritePaths=/var/lib/glyph-anchor

[Install]
WantedBy=multi-user.target
```

### 18.6 Startup Integrity Check

Before accepting any connections, the server must:

```rust
// 1. Verify identity file permissions
let metadata = fs::metadata(&identity_path)?;
let permissions = metadata.permissions();
if permissions.mode() & 0o177 != 0 {
    anyhow::bail!("Identity file permissions too open: {:o}. Must be 0600.", permissions.mode());
}

// 2. Open redb and verify integrity
let db = Database::open(&vault_path)?;
// Database::open() performs WAL recovery automatically — no explicit check needed
// If DB is corrupted beyond WAL recovery, open() returns Err — server exits

// 3. Verify vault table can be opened
{
    let read_txn = db.begin_read()?;
    let _vault = read_txn.open_table(VAULT)?;
}

// 4. Log startup information (safe — server's own addresses, no peer data)
tracing::info!(peer_id = %local_peer_id, version = env!("CARGO_PKG_VERSION"), "Glyph Anchor Server started");
```

---

# §19 PERFORMANCE OPTIMIZATION

### 19.1 Allocator: mimalloc

```rust
// main.rs — MUST be present, not just in Cargo.toml
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
```

**Without `#[global_allocator]`**, declaring `mimalloc` in Cargo.toml does nothing — the system allocator (glibc malloc) runs. This line is the entire difference between using mimalloc and not.

**Why mimalloc for this server:**
- Network servers allocate and free thousands of short-lived objects per second: connection state, stream frames, Noise handshake buffers, request/response CBOR buffers
- mimalloc uses thread-local heaps with no global lock for small allocations
- Throughput improvement: 2–4× vs glibc malloc for network server allocation patterns
- Security: randomized heap base address per thread, making heap exploitation harder

### 19.2 QUIC 0-RTT Connection Resumption

Mobile clients that disconnect and reconnect (network handoff, app backgrounding) benefit from QUIC's 0-RTT:
- First connection: 1 RTT for handshake
- Resumed connection: 0 RTT — client sends data in the first packet
- Reduces reconnect latency from ~100-300ms (TCP + TLS) to ~0ms (QUIC 0-RTT)

This directly improves offline message delivery: when a mobile device reconnects to the server to fetch pending vault entries, it can send the Fetch request in the first packet rather than after a full handshake.

### 19.3 Zero-Copy Vault Payloads

The encrypted payload bytes travel: network → Noise decrypt buffer → `Vec<u8>` request field → redb write.

Optimization: use `bytes::Bytes` for the payload field to enable reference counting rather than copying:

```rust
// In GlyphRequest:
Store {
    recipient_hash: [u8; 32],
    payload: bytes::Bytes,  // Reference-counted — no extra copy when serializing to redb
},

// In VaultEntry:
pub struct VaultEntry {
    pub stored_at: u64,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,  // redb needs &[u8], so we accept the one copy here
}
```

The payload copy count from network to disk: 1 copy (network buffer → redb value). No intermediate copies.

### 19.4 Batch Vault Operations

For the Fetch operation that retrieves multiple envelopes, all envelopes are fetched and deleted in a **single** redb write transaction. This is O(n) where n = envelope count, and involves one WAL flush per fetch regardless of envelope count.

Naive alternative (one transaction per envelope): O(n) WAL flushes. At 500 envelopes, the difference is ~499 fsync calls. Batch operation is critical for performance.

### 19.5 DashMap Shard Configuration

`DashMap` defaults to `num_cpus * 4` shards. For a server with 10,000 concurrent connections doing per-IP and per-peer lookups, increase shards:

```rust
let ip_connections: DashMap<IpAddr, IpRecord> = DashMap::with_capacity_and_shard_amount(
    1024,    // Initial capacity
    64,      // Shards — reduces lock contention under high concurrency
);
```

### 19.6 Tokio Runtime Configuration

```rust
#[tokio::main(flavor = "multi_thread", worker_threads = 0)]  // 0 = auto = num_cpus
async fn main() -> anyhow::Result<()> {
```

With `worker_threads = 0`, Tokio uses `num_cpus::get()` threads. This is correct for CPU-bound event dispatch. For I/O-bound servers, the default is also fine since Tokio tasks yield on await points.

**Critical:** All redb operations (read and write) must run in `spawn_blocking`. redb write transactions acquire an exclusive write lock using OS file locking — blocking the Tokio thread is forbidden. Read transactions under MVCC are lock-free and could technically run on the Tokio thread, but `spawn_blocking` is safer and prevents any unintended blocking.

### 19.7 Connection Accept Backlog

```
OS listen backlog: 1024  (set in TcpConfig)
```

The OS TCP listen queue holds SYN packets before the application accepts them. Under load spikes (many simultaneous inbound connections), a shallow backlog causes connections to be rejected at the TCP SYN level — before any application logic runs. 1024 is sufficient for bursts.

### 19.8 Release Profile (Final)

```toml
[profile.release]
opt-level = 3          # Maximum LLVM optimization
lto = true             # Link-time optimization across crate boundaries
codegen-units = 1      # Single LLVM codegen unit — enables full LTO
panic = "abort"        # No unwinding — smaller binary, faster on panic
strip = true           # Remove debug symbols — not needed in production
overflow-checks = true # Keep integer overflow checks — security-relevant
```

**`overflow-checks = true` in release:** Integer overflow in release mode without this flag wraps silently (two's complement). For sequence numbers, size calculations, and rate limit counters, silent wrapping can create security bugs (wrap from u32::MAX to 0 bypasses rate limits). Explicitly enable checks. The performance impact is < 1% on modern CPUs with branch prediction.

---

# §20 MEMORY SAFETY

### 20.1 Sensitive Data Lifecycle

```rust
use zeroize::Zeroize;

// Keypair secret bytes: zeroized immediately after file write
let mut secret_bytes: [u8; 64] = ed25519.secret().as_ref().try_into()?;
fs::write(&tmp_path, &secret_bytes)?;
secret_bytes.zeroize();  // Cleared before function return

// Decrypted push tokens: zeroized after blinding
let mut raw_token: Vec<u8> = ecies_decrypt(&encrypted_token, &server_privkey)?;
let blinded = blind_token(&raw_token, &server_secret);
raw_token.zeroize();     // Cleared immediately after blinding

// Webhook token decryption: zeroized after send
let mut decrypted = decrypt_token(&stored_value, &server_secret);
send_webhook(&decrypted, ...).await;
decrypted.zeroize();
```

### 20.2 Arc Usage for Shared State

All shared state is wrapped in `Arc` for safe concurrent access without locking the entire state:

```rust
struct ServerState {
    db: Arc<Database>,               // redb — thread-safe
    shield: Arc<SybilShield>,        // DashMap — thread-safe
    peer_pubkeys: Arc<DashMap<PeerId, identity::PublicKey>>,
    http_client: Arc<reqwest::Client>, // Connection pool — thread-safe
    server_secret: Arc<[u8; 32]>,    // Static secret for token blinding
}
```

`Arc` clones are cheap (atomic increment). The underlying data is not copied.

### 20.3 No Persistent Heap Secrets

The server's private key is used once at startup (to complete Noise handshakes, handled by libp2p). It is held by the `Swarm` in a `Keypair` struct. Libp2p's Noise implementation uses this for session key derivation. The session keys are ephemeral and exist only for the duration of a connection.

The server does not implement any additional key material management. No key caching, no derived keys stored in fields.

---

# §21 OPERATIONAL SECURITY

### 21.1 Log Policy — What to Log

```
ALLOWED — Server operational state (no user-identifying data):

tracing::info!(addr = %addr, "Listening on {addr}");
tracing::info!(peer_id = %local_peer_id, "Server identity");
tracing::info!(
    active_connections = N,
    active_circuits = M,
    vault_entries = K,
    "Periodic metrics"
);
tracing::info!(pruned_count = N, "TTL prune complete");
tracing::warn!("Webhook delivery failed after 3 attempts");  // aggregate only
tracing::error!(err = %e, "Fatal: could not open vault database");
```

### 21.2 Log Policy — What Never to Log

```
FORBIDDEN — Never appears in any log line:

❌ Any PeerId (remote peer's identity)
❌ Any Multiaddr of a remote peer (their IP address)
❌ Any vault key (recipient hash)
❌ Any vault payload (even its length per entry is discouraged)
❌ Any circuit pair (which PeerId is relaying to which)
❌ Any push token (raw or blinded)
❌ Private key bytes or derived secrets
❌ Noise session parameters
❌ Sender information of any kind
```

### 21.3 Structured Logging Format

```rust
tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::from_default_env())
    .json()  // Machine-parseable JSON lines
    .with_current_span(false)  // No span IDs in output (minimize log size)
    .with_thread_ids(false)
    .with_file(false)          // No source file paths in production
    .with_line_number(false)
    .init();
```

JSON logging allows structured log aggregation (Elasticsearch, Loki, Grafana Cloud) without log parsing regex.

### 21.4 File System Permissions

```
/var/lib/glyph-anchor/               owner: glyph-server:glyph-server, mode: 0700
/var/lib/glyph-anchor/.glyph_identity  owner: glyph-server, mode: 0600
/var/lib/glyph-anchor/vault.redb       owner: glyph-server, mode: 0600
/var/lib/glyph-anchor/tokens.redb      owner: glyph-server, mode: 0600
/usr/local/bin/glyph-anchor-server     owner: root, mode: 0755
```

The server process runs as `glyph-server` (non-root). It cannot write to `/usr/local/bin/` or modify its own binary. systemd's `ProtectSystem=strict` enforces this at the OS level.

### 21.5 Environment Variables

```bash
GLYPH_IDENTITY_PATH=/var/lib/glyph-anchor/.glyph_identity  # default
GLYPH_VAULT_PATH=/var/lib/glyph-anchor/vault.redb          # default
GLYPH_TOKENS_PATH=/var/lib/glyph-anchor/tokens.redb        # default
GLYPH_WEBHOOK_URL=https://push.internal/notify              # required for push
GLYPH_WEBHOOK_SECRET=<32 hex bytes>                         # required for push
GLYPH_SERVER_SECRET=<32 hex bytes>                          # required for token blinding
RUST_LOG=glyph_anchor=info                                  # default log level
```

Server secret values are passed via environment variables set in the systemd unit's `EnvironmentFile=` directive — not on the command line (which would appear in process listings).

---

# §22 NON-REQUIREMENTS

Explicit rejections. These are not oversights — each exclusion maintains the zero-metadata guarantee.

| Feature | Exclusion Reason |
|---|---|
| User accounts / registration | No identity system. PeerId is the only identifier. Adding accounts creates a username database. |
| REST HTTP API | All communication via libp2p protocols. An HTTP endpoint would require parsing HTTP headers — a new metadata surface. |
| Admin dashboard or web UI | Operational state via structured JSON logs only. A UI implies persistent request logging. |
| GossipSub | Pub-sub broadcast protocol. Fanout creates membership lists — who is subscribed to what. Incompatible with zero social-graph guarantee. |
| Message deduplication | Requires content inspection (hash of plaintext) or global message IDs. Both break the blind architecture. |
| Delivery receipts to sender | Would reveal that sender's message was retrieved, and when. This links sender to recipient. |
| Sender identity in vault | Explicit. The Store request type has no sender field. |
| Read receipts | Would create a social graph edge (A sent to B, B read it). |
| Presence / online indicators | Who is online at what time is metadata. Not collected. |
| Message expiry control by sender | Sender cannot set per-message TTL. Server TTL is non-negotiable (30 days max). Allowing sender-controlled TTL leaks that a specific hash has an awaiting sender. |
| Server-side search or indexing | Server cannot index what it cannot read. |
| WebRTC signaling | WebRTC requires SDP negotiation which leaks ICE candidates (IP addresses). libp2p DCUtR is the correct alternative. |
| STUN/TURN | STUN/TURN is the WebRTC-ecosystem solution to the same problem Circuit Relay v2 + DCUtR solve. Redundant. TURN would create a second credential system. |
| Tor hidden service (.onion) on server | Server must have a stable, reachable IP for bootstrapping. Tor integration is client-side (Arti). Server-side Tor would make server unreachable to non-Tor clients. |
| Server federation | Multiple servers would require gossip protocols between servers — creates inter-server metadata leakage. Future work if needed, but out of scope. |

---

# §23 PERFORMANCE TARGETS

| Metric | Target | Measurement |
|---|---|---|
| Concurrent inbound connections | 10,000 | Sustained, not burst |
| New connections per second (peak) | 1,000 | Burst tolerance |
| QUIC 0-RTT reconnect latency | < 5ms server-side processing | Excluding network RTT |
| Relay throughput (aggregate) | 1 Gbps | iperf3 through relay |
| Vault Store ops/sec | 5,000 | redb write throughput with spawn_blocking pool |
| Vault Fetch ops/sec | 2,000 | redb MVCC read throughput |
| DHT query response time (P99) | < 50ms server-processing | Not including client RTT |
| Cold start time | < 2 seconds | Identity load + port bind + DHT bootstrap |
| Warm start time (after panic=abort) | < 500ms | redb WAL recovery + port bind |
| RAM usage (idle, 0 connections) | < 64 MB | RSS |
| RAM usage (10k connections) | < 2 GB | RSS — ~200KB per connection |
| Vault disk I/O (Store, WAL) | < 200 μs per commit | NVMe; HDD will be ~5ms |

---

# §24 COMPLETE DEPENDENCY MANIFEST

```toml
[package]
name    = "glyph-anchor-server"
version = "0.2.0"
edition = "2021"

[dependencies]
# ── Async Runtime ────────────────────────────────────────────────────────
tokio                = { version = "1.38", features = ["full"] }

# ── Networking ───────────────────────────────────────────────────────────
libp2p               = { version = "0.54", features = [
    "tcp",               # TCP transport
    "quic",              # QUIC/UDP transport (primary)
    "dns",               # Multiaddr /dns4/ resolution
    "yamux",             # Stream multiplexer
    "noise",             # Noise XX security
    "kad",               # Kademlia DHT
    "relay",             # Circuit Relay v2 server
    "dcutr",             # Direct Connection Upgrade through Relay
    "request-response",  # Store-and-Forward protocol
    "cbor",              # CBOR codec for request-response
    "identify",          # Peer identity exchange
    "ping",              # Connection liveness
    "macros",            # #[derive(NetworkBehaviour)]
    "tokio",             # Tokio runtime integration
]}
# NOTE: libp2p-request-response standalone crate NOT needed — included above

# ── Concurrency / Collections ────────────────────────────────────────────
dashmap              = { version = "6.0", features = ["serde"] }
bytes                = "1.6"

# ── Storage ──────────────────────────────────────────────────────────────
redb                 = "2.1"         # Replaces sled — ACID, WAL, pure Rust, maintained

# ── Serialization ────────────────────────────────────────────────────────
serde                = { version = "1.0", features = ["derive"] }
ciborium             = "0.2"         # CBOR — wire protocol serialization
serde_json           = "1.0"         # JSON — config files and webhook payloads only
serde_bytes          = "0.11"        # Efficient byte array serialization

# ── Cryptography ─────────────────────────────────────────────────────────
sha2                 = "0.10"        # SHA256 for vault keys and token blinding
hmac                 = "0.12"        # HMAC-SHA256 for webhook signing
zeroize              = "1.7"         # Zero sensitive memory after use

# ── Logging ──────────────────────────────────────────────────────────────
tracing              = "0.1"
tracing-subscriber   = { version = "0.3", features = ["env-filter", "json"] }

# ── HTTP (Webhooks only) ─────────────────────────────────────────────────
reqwest              = { version = "0.12", features = ["json"] }

# ── Error Handling ───────────────────────────────────────────────────────
anyhow               = "1.0"

# ── Async Utilities ──────────────────────────────────────────────────────
futures              = "0.3"

# ── Performance ──────────────────────────────────────────────────────────
mimalloc             = { version = "0.1", default-features = false }

# ── Random ───────────────────────────────────────────────────────────────
rand                 = "0.8"         # For pruner jitter

[profile.release]
opt-level        = 3
lto              = true
codegen-units    = 1
panic            = "abort"       # CORRECTED from "unwind"
strip            = true
overflow-checks  = true

[profile.dev]
overflow-checks  = true
```

**Removed from original Cargo.toml:**
- `sled 0.34` → **replaced with `redb 2.1`**
- `libp2p-request-response = "0.27"` → **removed (redundant with libp2p "request-response" feature)**
- `panic = "unwind"` → **corrected to `panic = "abort"`**

**Added vs original:**
- `ciborium` — CBOR serialization for wire protocol
- `hmac` — webhook signing
- `zeroize` — memory safety for secrets
- `ciborium`, `serde_bytes` — efficient serialization
- `rand` — pruner startup jitter

---

# §25 COMPLETE RUST TYPE DEFINITIONS

```rust
// ── Global Allocator ─────────────────────────────────────────────────────
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// ── NetworkBehaviour ─────────────────────────────────────────────────────
#[derive(NetworkBehaviour)]
pub struct GlyphAnchorBehaviour {
    pub kad:              kad::Behaviour<kad::store::MemoryStore>,
    pub relay:            relay::server::Behaviour,
    pub dcutr:            dcutr::Behaviour,
    pub request_response: request_response::Behaviour<GlyphVaultCodec>,
    pub identify:         identify::Behaviour,
    pub ping:             ping::Behaviour,
}

// ── Swarm Event Type (derived from above) ───────────────────────────────
// GlyphAnchorEvent is auto-generated by #[derive(NetworkBehaviour)]
// Variants: Kad(..), Relay(..), Dcutr(..), RequestResponse(..), Identify(..), Ping(..)

// ── Wire Protocol ────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GlyphRequest {
    Store {
        recipient_hash: [u8; 32],
        payload:        Vec<u8>,
    },
    Fetch,
    RegisterToken {
        recipient_hash:  [u8; 32],
        encrypted_token: Vec<u8>,
        expiry:          u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GlyphResponse {
    StoreAck         { success: bool },
    FetchResult      { payloads: Vec<Vec<u8>> },
    RegisterTokenAck { success: bool },
    Error            { code: u16 },
}

// ── Vault Storage Types ──────────────────────────────────────────────────
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultEntry {
    pub stored_at: u64,       // Unix seconds — TTL only
    pub payload:   Vec<u8>,   // Opaque encrypted bytes — server never reads
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindedToken {
    pub blind_key:       [u8; 32],  // SHA256(raw_token || server_secret)
    pub encrypted_token: Vec<u8>,   // ChaCha20-Poly1305(raw_token, server_secret)
    pub expiry:          u64,
}

// ── redb Table Definitions ───────────────────────────────────────────────
const VAULT:  TableDefinition<&[u8], &[u8]> = TableDefinition::new("vault_v1");
const TOKENS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tokens_v1");
const SEQNO:  TableDefinition<&[u8], u64>   = TableDefinition::new("seqno_v1");

// ── Sybil Shield State ───────────────────────────────────────────────────
pub struct SybilShield {
    pub ip_connections:  DashMap<IpAddr, IpRecord>,
    pub peer_vault_ops:  DashMap<PeerId, VaultRateRecord>,
    pub peer_dht_ops:    DashMap<PeerId, DhtRateRecord>,
    pub relay_denials:   AtomicU64,
    pub circuit_denials: AtomicU64,
    pub vault_rejects:   AtomicU64,
}

pub struct IpRecord {
    pub active:      AtomicU32,
    pub rate_count:  AtomicU32,
    pub window:      Mutex<Instant>,
}

pub struct VaultRateRecord {
    pub ops:    AtomicU32,
    pub window: Mutex<Instant>,
}

// ── Constants ────────────────────────────────────────────────────────────
pub const MAX_ENVELOPE_SIZE:             usize = 64 * 1024;   // 64 KB
pub const MAX_ENVELOPES_PER_RECIPIENT:   usize = 500;
pub const TTL_SECONDS:                   u64   = 30 * 24 * 3600; // 30 days
pub const MAX_CONNECTIONS_PER_IP:        u32   = 20;
pub const MAX_NEW_CONNECTIONS_PER_MIN:   u32   = 30;
pub const MAX_VAULT_OPS_PER_PEER_PER_MIN: u32  = 15;
pub const VAULT_PORT:                    u16   = 5678;

// ── Server Configuration (from environment) ──────────────────────────────
pub struct ServerConfig {
    pub identity_path:  PathBuf,
    pub vault_path:     PathBuf,
    pub tokens_path:    PathBuf,
    pub webhook_url:    Option<String>,
    pub webhook_secret: Option<[u8; 32]>,
    pub server_secret:  [u8; 32],
}

impl ServerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let server_secret_hex = std::env::var("GLYPH_SERVER_SECRET")
            .context("GLYPH_SERVER_SECRET must be set")?;
        let secret_bytes = hex::decode(&server_secret_hex)
            .context("GLYPH_SERVER_SECRET must be 64 hex characters")?;
        anyhow::ensure!(secret_bytes.len() == 32, "GLYPH_SERVER_SECRET must be 32 bytes");
        
        Ok(Self {
            identity_path: PathBuf::from(
                std::env::var("GLYPH_IDENTITY_PATH")
                    .unwrap_or_else(|_| ".glyph_identity".into())
            ),
            vault_path: PathBuf::from(
                std::env::var("GLYPH_VAULT_PATH")
                    .unwrap_or_else(|_| "vault.redb".into())
            ),
            tokens_path: PathBuf::from(
                std::env::var("GLYPH_TOKENS_PATH")
                    .unwrap_or_else(|_| "tokens.redb".into())
            ),
            webhook_url:    std::env::var("GLYPH_WEBHOOK_URL").ok(),
            webhook_secret: None, // parsed separately
            server_secret:  secret_bytes.try_into().unwrap(),
        })
    }
}
```

---

# §26 FORMAL PRIVACY PROOF

### 26.1 Axioms

```
A1: SHA256 is a preimage-resistant hash function.
    Given y = SHA256(x), computing x from y is computationally infeasible.

A2: The E2E encryption scheme used by Glyph clients is semantically secure.
    Given C = Enc(K, M), M cannot be recovered without K.

A3: The Noise XX handshake achieves mutual authentication.
    After handshake completion, both sides know they are speaking to
    the holder of the claimed private key.

A4: The server's data model is fixed — no server-side modifications
    can add new fields to stored records at runtime without redeployment.
```

### 26.2 Theorem: Sender Anonymity Under Storage-Access Attack

**Theorem:** An adversary with full read access to the server's storage cannot determine the sender of any vault entry.

**Proof:**
1. The vault entry schema is `VaultEntry { stored_at: u64, payload: Vec<u8> }`.
2. The schema has no sender field. (A4 — cannot be changed at runtime.)
3. The store handler accepts `GlyphRequest::Store { recipient_hash, payload }` — no sender parameter.
4. The event loop handler for Store does not inject sender information.
5. Therefore, no sender information enters the storage subsystem.
6. Therefore, storage-access adversary cannot read what was never written. ∎

### 26.3 Theorem: Recipient Pseudonymity Under Storage-Access Attack

**Theorem:** An adversary with full read access to the server's storage cannot determine the human identity of any vault entry recipient without also compromising the recipient's client device.

**Proof:**
1. Vault entries are keyed by `k = SHA256(recipient_pubkey_bytes)`.
2. By A1, computing `recipient_pubkey` from `k` is infeasible.
3. The recipient's human identity (username, phone number, email) is never stored on the server (A4, store handler schema).
4. The mapping from `recipient_pubkey` to human identity exists only in the recipient's contacts on other client devices.
5. Therefore, storage-access adversary obtains only `k` — an opaque hash — which is not linkable to any human identity without compromising a client device. ∎

### 26.4 Theorem: Content Confidentiality Under Full Server Compromise

**Theorem:** An adversary with full server compromise (storage + RAM + process memory) cannot read the content of any vault entry.

**Proof:**
1. Each payload `C = Enc(K_B, M)` is encrypted by the sender with the recipient's public key `K_B`.
2. The server never receives `K_B` (the private key) — it only receives the ciphertext `C`.
3. By A2, `M` cannot be recovered from `C` without `K_B`.
4. `K_B` is not stored on the server (A4).
5. `K_B` is not held in the server's RAM (never received as input).
6. Therefore, even full server compromise yields only `C`, from which `M` is unrecoverable. ∎

### 26.5 Social Graph Unrecoverability

**Theorem:** An adversary with full server compromise cannot reconstruct the social graph of Glyph users.

**Proof:**
1. The social graph consists of edges `(A, B)` meaning "A sent a message to B."
2. From §26.2, the server does not know `A` (sender) for any vault entry.
3. From §26.3, the server knows only `SHA256(pubkey(B))`, not `B`'s identity.
4. Circuit relay pairs `(PeerId_A, PeerId_B)` are not logged (§9.4).
5. DHT queries `(querier_PeerId, target_PeerId)` are not logged (§8.5).
6. Therefore, no edge `(A, B)` can be recovered from any server data. ∎

### 26.6 What Remains True Under Non-Privacy Threat: Legal Compulsion

A legal compulsion (subpoena) of the server operator yields:
- redb vault file: `{ SHA256(pubkey) → ciphertext }` — see §26.3 and §26.4
- redb token file: `{ SHA256(token||secret) → AES-GCM(token, secret) }` — without `GLYPH_SERVER_SECRET`, unreadable
- Process logs: aggregate counts and server events — no user-identifying information
- Server binary: the compiled Rust code — contains no user data
- Environment variables (if accessible): `GLYPH_SERVER_SECRET` and `GLYPH_WEBHOOK_SECRET` — these allow decrypting stored tokens but not vault contents or social graph

**Conclusion:** The only piece of data accessible under legal compulsion that could be sensitive is the stored push tokens (if `GLYPH_SERVER_SECRET` is also compelled). Push token → device linkage is the residual risk. Mitigation: use a separate HSM or remote secret storage for `GLYPH_SERVER_SECRET` that cannot be compelled along with the server.

---

*END OF DOCUMENT*

**Glyph Hybrid Anchor Server — Engineering Specification v2.0**  
**Total Coverage: Transport → Crypto → DHT → Relay → DCUtR → Vault → Event Loop → Sybil Shield → TTL → Webhooks → Crash Resistance → Performance → Privacy Proof**
