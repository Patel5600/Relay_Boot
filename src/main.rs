use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::error::Error;
use std::fs;
use std::sync::Arc;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, Instant, UNIX_EPOCH};
use dashmap::DashMap;
use libp2p::{identity, Multiaddr, swarm::SwarmEvent, PeerId, SwarmBuilder, request_response};
use futures::stream::StreamExt;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use anyhow::Context;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use redb::ReadableTable;
use base64::Engine as _;

mod network;
mod storage;

use network::{GlyphAnchorBehaviour, GlyphRequest, GlyphResponse};
use storage::{RedbStorage, VaultEntry, VAULT, WebhookTask};

// ── Sybil Shield Rate Limiting ───────────────────────────────────────────
pub struct SybilShield {
    pub ip_connections: DashMap<IpAddr, IpRecord>,
    pub peer_vault_ops: DashMap<PeerId, VaultRateRecord>,
    pub relay_denials: AtomicU64,
    pub circuit_denials: AtomicU64,
    pub vault_rejects: AtomicU64,
}

pub struct IpRecord {
    pub active: AtomicU32,
    pub rate_count: AtomicU32,
    pub window: Mutex<Instant>,
}

pub struct VaultRateRecord {
    pub ops: AtomicU32,
    pub window: Mutex<Instant>,
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            // Zero out the host portion (last 8 bytes of 16-byte IPv6) to group by /64 prefix
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

impl SybilShield {
    pub fn new() -> Self {
        Self {
            ip_connections: DashMap::new(),
            peer_vault_ops: DashMap::new(),
            relay_denials: AtomicU64::new(0),
            circuit_denials: AtomicU64::new(0),
            vault_rejects: AtomicU64::new(0),
        }
    }

    pub fn check_and_register_connection(&self, raw_ip: IpAddr) -> bool {
        let ip = normalize_ip(raw_ip);
        let record = self.ip_connections.entry(ip).or_insert_with(|| IpRecord {
            active: AtomicU32::new(0),
            rate_count: AtomicU32::new(0),
            window: Mutex::new(Instant::now()),
        });

        // 1. Check active connection limit (20)
        let active = record.active.load(Ordering::Relaxed);
        if active >= 20 {
            return false;
        }

        // 2. Check rate limit (30 per 60s)
        let mut window_start = record.window.lock().unwrap();
        if window_start.elapsed() >= std::time::Duration::from_secs(60) {
            record.rate_count.store(0, Ordering::Relaxed);
            *window_start = Instant::now();
        }
        let rate = record.rate_count.fetch_add(1, Ordering::Relaxed);
        if rate >= 30 {
            return false;
        }

        record.active.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn deregister_connection(&self, raw_ip: IpAddr) {
        let ip = normalize_ip(raw_ip);
        if let Some(record) = self.ip_connections.get(&ip) {
            record.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn check_vault_ratelimit(&self, peer: &PeerId) -> bool {
        let record = self.peer_vault_ops.entry(*peer).or_insert_with(|| VaultRateRecord {
            ops: AtomicU32::new(0),
            window: Mutex::new(Instant::now()),
        });

        let mut window_start = record.window.lock().unwrap();
        if window_start.elapsed() >= std::time::Duration::from_secs(60) {
            record.ops.store(0, Ordering::Relaxed);
            *window_start = Instant::now();
        }

        let total = record.ops.fetch_add(1, Ordering::Relaxed);
        if total >= 15 {
            self.vault_rejects.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub fn cleanup_stale_records(&self) {
        self.ip_connections.retain(|_, record| {
            record.active.load(Ordering::Relaxed) > 0
                || record.window.lock().unwrap().elapsed() < std::time::Duration::from_secs(300)
        });
        self.peer_vault_ops.retain(|_, record| {
            record.window.lock().unwrap().elapsed() < std::time::Duration::from_secs(300)
        });
    }
}

// ── Server Configuration ─────────────────────────────────────────────────
pub struct ServerConfig {
    pub identity_path:  std::path::PathBuf,
    pub vault_path:     std::path::PathBuf,
    pub tokens_path:    std::path::PathBuf,
    pub webhook_url:    Option<String>,
    pub webhook_secret: Option<[u8; 32]>,
    pub server_secret:  [u8; 32],
}

impl ServerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let secret_bytes = if let Ok(cred_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
            let cred_path = std::path::Path::new(&cred_dir).join("glyph_server_secret");
            if cred_path.exists() {
                let raw_bytes = std::fs::read(&cred_path)
                    .context("Failed to read systemd credential 'glyph_server_secret'")?;
                if raw_bytes.len() == 32 {
                    raw_bytes
                } else {
                    let content_str = String::from_utf8(raw_bytes)
                        .context("Systemd credential is not valid UTF-8 and not 32 bytes raw binary")?;
                    hex::decode(content_str.trim())
                        .context("Systemd credential must be either 32 raw bytes or 64 hex characters")?
                }
            } else {
                let server_secret_hex = std::env::var("GLYPH_SERVER_SECRET")
                    .context("GLYPH_SERVER_SECRET must be set (no systemd credentials found)")?;
                hex::decode(server_secret_hex.trim())
                    .context("GLYPH_SERVER_SECRET must be 64 hex characters")?
            }
        } else {
            let server_secret_hex = std::env::var("GLYPH_SERVER_SECRET")
                .context("GLYPH_SERVER_SECRET must be set")?;
            hex::decode(server_secret_hex.trim())
                .context("GLYPH_SERVER_SECRET must be 64 hex characters")?
        };

        anyhow::ensure!(secret_bytes.len() == 32, "Server secret must be 32 bytes");
        
        Ok(Self {
            identity_path: std::path::PathBuf::from(
                std::env::var("GLYPH_IDENTITY_PATH")
                    .unwrap_or_else(|_| ".glyph_identity".into())
            ),
            vault_path: std::path::PathBuf::from(
                std::env::var("GLYPH_VAULT_PATH")
                    .unwrap_or_else(|_| "vault.redb".into())
            ),
            tokens_path: std::path::PathBuf::from(
                std::env::var("GLYPH_TOKENS_PATH")
                    .unwrap_or_else(|_| "tokens.redb".into())
            ),
            webhook_url:    std::env::var("GLYPH_WEBHOOK_URL").ok(),
            webhook_secret: None, // parsed separately if needed
            server_secret:  secret_bytes.try_into().unwrap(),
        })
    }
}

// ── Symmetric Blind Token Encryption/Decryption ──────────────────────────
fn xor_cipher(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 32])
        .collect()
}

fn decrypt_token(encrypted: &[u8], key: &[u8; 32]) -> Vec<u8> {
    xor_cipher(encrypted, key)
}

// ── Webhook Delivery Engine ──────────────────────────────────────────────
async fn webhook_engine(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<WebhookTask>,
    storage: Arc<RedbStorage>,
    server_secret: [u8; 32],
    webhook_url: Option<String>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    loop {
        tokio::select! {
            task_opt = rx.recv() => {
                let Some(task) = task_opt else { break };
                
                // Fetch and remove token from database
                let token_opt = match storage.take_blinded_token(&task.recipient_hash) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("Webhook Engine: Failed to query token: {:?}", e);
                        continue;
                    }
                };

                if let Some(token) = token_opt {
                    if let Some(ref url) = webhook_url {
                        let raw_token = decrypt_token(&token.encrypted_token, &server_secret);
                        info!("Webhook Engine: Dispatched wake-up notification to push gateway...");
                        send_webhook_request(&client, url, &raw_token, &server_secret).await;
                    }
                }
            }
            _ = shutdown.recv() => {
                info!("Webhook Engine: Shutting down");
                break;
            }
        }
    }
}

async fn send_webhook_request(
    client: &reqwest::Client,
    webhook_url: &str,
    raw_token: &[u8],
    server_secret: &[u8; 32],
) {
    let payload = serde_json::json!({
        "token": base64::prelude::BASE64_STANDARD.encode(raw_token),
        "notification": {}
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // HMAC signature
    let mut mac = Hmac::<Sha256>::new_from_slice(server_secret).unwrap();
    mac.update(&payload_bytes);
    let signature = hex::encode(mac.finalize().into_bytes());

    for attempt in 0..3u32 {
        let delay = std::time::Duration::from_secs(5u64.pow(attempt));
        if attempt > 0 {
            tokio::time::sleep(delay).await;
        }

        let result = client
            .post(webhook_url)
            .header("Content-Type", "application/json")
            .header("X-Glyph-Signature", &signature)
            .body(payload_bytes.clone())
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                info!("Webhook Engine: Push notification request successfully dispatched.");
                return;
            }
            Ok(resp) => {
                warn!("Webhook Engine: Push gateway returned non-2xx status: {:?}", resp.status());
            }
            Err(e) => {
                warn!("Webhook Engine: Failed to dispatch push notification: {:?}", e);
            }
        }
    }
    warn!("Webhook Engine: Webhook delivery failed after 3 attempts");
}

// ── Startup Identity Loader ──────────────────────────────────────────────
pub fn load_or_generate_keypair(path: &std::path::Path) -> identity::Keypair {
    if path.exists() {
        let bytes = fs::read(path).expect("Failed to read keypair file");
        identity::Keypair::from_protobuf_encoding(&bytes)
            .expect("Failed to decode keypair from protobuf encoding")
    } else {
        let mut seed = [0u8; 32];
        let secret_key = identity::ed25519::SecretKey::try_from_bytes(&mut seed).unwrap();
        let keypair = identity::Keypair::from(identity::ed25519::Keypair::from(secret_key));
        let bytes = keypair
            .to_protobuf_encoding()
            .expect("Failed to encode keypair to protobuf");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("Failed to create parent directory for identity file");
        }
        fs::write(path, bytes).expect("Failed to write keypair file");
        keypair
    }
}

// ── Utility: Extract IP Address from Connected Endpoint ──────────────────
fn extract_ip(endpoint: &libp2p::core::ConnectedPoint) -> Option<IpAddr> {
    let addr = match endpoint {
        libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
        libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
    };
    for protocol in addr.iter() {
        match protocol {
            libp2p::core::multiaddr::Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            libp2p::core::multiaddr::Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => {}
        }
    }
    None
}

// ── Main Event Loop ──────────────────────────────────────────────────────
fn main() -> Result<(), Box<dyn Error>> {
    let use_json = std::env::var("GLYPH_LOG_JSON")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if use_json {
        let subscriber = FmtSubscriber::builder()
            .json()
            .with_max_level(Level::INFO)
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
    } else {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(32)
        .global_queue_interval(61)
        .build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn Error>> {
    info!("🌌 Initializing Glyph Hybrid Anchor Node v0.2.0...");

    let config = ServerConfig::from_env()?;

    // Load or generate identity keypair
    let local_key = load_or_generate_keypair(&config.identity_path);
    let local_peer_id = local_key.public().to_peer_id();
    info!("Static PeerId: {}", local_peer_id);

    // Initialize Redb Storage & SybilShieldConnection limits
    let storage = Arc::new(RedbStorage::new(config.vault_path.to_str().unwrap()));
    let shield = Arc::new(SybilShield::new());

    // Peer pubkey cache for request-response Fetch authentication
    let peer_pubkeys = Arc::new(DashMap::<PeerId, identity::PublicKey>::new());

    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::unbounded_channel::<WebhookTask>();
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Spawn webhook delivery engine background task
    tokio::spawn(webhook_engine(
        webhook_rx,
        storage.clone(),
        config.server_secret,
        config.webhook_url.clone(),
        shutdown_tx.subscribe(),
    ));

    // Spawn pruner background task
    let db_clone = storage.get_db();
    tokio::spawn(start_pruner(db_clone, shutdown_tx.subscribe()));

    // Build Swarm using SwarmBuilder
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic_config(|mut quic_conf| {
            quic_conf.max_concurrent_stream_limit = 1000;
            quic_conf.max_stream_data = 32 * 1024 * 1024;
            quic_conf.max_connection_data = 64 * 1024 * 1024;
            quic_conf
        })
        .with_dns_config(
            libp2p::dns::ResolverConfig::cloudflare(),
            libp2p::dns::ResolverOpts::default(),
        )
        .with_behaviour(|keypair: &identity::Keypair| {
            let local_peer = keypair.public().to_peer_id();

            // 1. Kademlia DHT MemoryStore behaviour
            let mut kad_config = libp2p::kad::Config::new(libp2p::StreamProtocol::new("/glyph/kad/1.0.0"));
            kad_config
                .set_query_timeout(std::time::Duration::from_secs(60))
                .set_replication_factor(std::num::NonZeroUsize::new(3).unwrap())
                .set_record_ttl(Some(std::time::Duration::from_secs(86400)))       // 24h
                .set_publication_interval(Some(std::time::Duration::from_secs(43200)))  // 12h
                .set_kbucket_pending_timeout(std::time::Duration::from_secs(60))
                .set_max_packet_size(16 * 1024);
            let store = libp2p::kad::store::MemoryStore::new(local_peer);
            let mut kad = libp2p::kad::Behaviour::with_config(local_peer, store, kad_config);
            kad.set_mode(Some(libp2p::kad::Mode::Server));

            // 2. Circuit Relay v2 server limits
            let mut relay_config = libp2p::relay::Config::default();
            relay_config.max_reservations = 128;
            relay_config.max_reservations_per_peer = 4;
            relay_config.reservation_duration = std::time::Duration::from_secs(3600);
            relay_config.max_circuits = 256;
            relay_config.max_circuits_per_peer = 8;
            relay_config.max_circuit_duration = std::time::Duration::from_secs(1800);
            relay_config.max_circuit_bytes = 100 * 1024 * 1024;
            let relay = libp2p::relay::Behaviour::new(local_peer, relay_config);

            // 3. Request-Response (CBOR) offline vault protocol
            let request_response = libp2p::request_response::cbor::Behaviour::<GlyphRequest, GlyphResponse>::new(
                [(libp2p::StreamProtocol::new("/glyph/vault/1.0.0"), libp2p::request_response::ProtocolSupport::Full)],
                libp2p::request_response::Config::default(),
            );

            // 4. Identify & Ping behaviors
            let identify_config = libp2p::identify::Config::new(
                "/glyph/1.0.0".to_string(),
                keypair.public(),
            ).with_agent_version("glyph-anchor/0.2.0".to_string());
            let identify = libp2p::identify::Behaviour::new(identify_config);
            let ping = libp2p::ping::Behaviour::new(
                libp2p::ping::Config::new()
                    .with_interval(std::time::Duration::from_secs(30))
                    .with_timeout(std::time::Duration::from_secs(10))
            );

            // 5. DCUtR direct connection upgrade helper
            let dcutr = libp2p::dcutr::Behaviour::new(local_peer);

            GlyphAnchorBehaviour {
                kad,
                relay,
                request_response,
                identify,
                ping,
                dcutr,
            }
        })?
        .build();

    let tcp_addr: Multiaddr = "/ip4/0.0.0.0/tcp/5678".parse()?;
    let quic_addr: Multiaddr = "/ip4/0.0.0.0/udp/5678/quic-v1".parse()?;
    
    swarm.listen_on(tcp_addr)?;
    swarm.listen_on(quic_addr)?;

    info!("Swarm dual-transports bound to port 5678. Server loop starting...");

    let mut pruner_ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
    let mut metrics_ticker = tokio::time::interval(std::time::Duration::from_secs(300));
    let mut shield_ticker = tokio::time::interval(std::time::Duration::from_secs(600));

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            // ── Primary: swarm events ──────────────────────────────────────
            event_opt = swarm.next() => {
                let Some(event) = event_opt else { break };
                
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on Multiaddress: {}/p2p/{}", address, local_peer_id);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        if let Some(ip) = extract_ip(&endpoint) {
                            if !shield.check_and_register_connection(ip) {
                                let _ = swarm.disconnect_peer_id(peer_id);
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, endpoint, .. } => {
                        if let Some(ip) = extract_ip(&endpoint) {
                            shield.deregister_connection(ip);
                        }
                        peer_pubkeys.remove(&peer_id);
                    }
                    SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                        network::GlyphAnchorBehaviourEvent::RequestResponse(request_response::Event::Message { peer, message }) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => {
                                    if !shield.check_vault_ratelimit(&peer) {
                                        let _ = swarm.behaviour_mut().request_response.send_response(channel, GlyphResponse::Error { code: 429 });
                                        continue;
                                    }

                                    let response = match request {
                                        GlyphRequest::Store { recipient_hash, payload } => {
                                            storage.vault_store(recipient_hash, payload, webhook_tx.clone())
                                                .await
                                                .unwrap_or(GlyphResponse::Error { code: 500 })
                                        }
                                        GlyphRequest::Fetch => {
                                            if let Some(pubkey) = peer_pubkeys.get(&peer) {
                                                storage.vault_fetch(pubkey.clone())
                                                    .await
                                                    .unwrap_or(GlyphResponse::Error { code: 500 })
                                            } else {
                                                // Identify has not finished yet, so public key is not cached
                                                GlyphResponse::Error { code: 403 }
                                            }
                                        }
                                        GlyphRequest::RegisterToken { recipient_hash, encrypted_token, expiry } => {
                                            let blind_key = {
                                                let mut hasher = Sha256::new();
                                                hasher.update(&encrypted_token);
                                                hasher.update(&config.server_secret);
                                                hasher.finalize().into()
                                            };
                                            storage.register_token(recipient_hash, blind_key, encrypted_token, expiry)
                                                .await
                                                .unwrap_or(GlyphResponse::Error { code: 500 })
                                        }
                                    };
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
                                }
                                _ => {}
                            }
                        }
                        network::GlyphAnchorBehaviourEvent::Identify(identify_event) => {
                            if let libp2p::identify::Event::Received { peer_id, info, .. } = identify_event {
                                peer_pubkeys.insert(peer_id, info.public_key.clone());
                                for addr in info.listen_addrs {
                                    swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                                }
                            }
                        }
                        network::GlyphAnchorBehaviourEvent::Ping(ping_event) => {
                            if let libp2p::ping::Event { peer, result: Ok(rtt), .. } = ping_event {
                                tracing::debug!("Liveness ping with peer {} returned RTT: {:?}", peer, rtt);
                            }
                        }
                        _ => {}
                    }
                    _ => {}
                }
            }

            // ── Hourly: TTL pruner ─────────────────────────────────────────
            _ = pruner_ticker.tick() => {
                // Done asynchronously by start_pruner loop
            }

            // ── 5-min: aggregate metrics ───────────────────────────────────
            _ = metrics_ticker.tick() => {
                let peers = swarm.network_info().num_peers();
                info!(
                    active_connections = peers,
                    vault_rejects = shield.vault_rejects.load(Ordering::Relaxed),
                    "Periodic metrics summary"
                );
            }

            // ── 10-min: cleanup rate limiting maps ──────────────────────────
            _ = shield_ticker.tick() => {
                shield.cleanup_stale_records();
            }

            // ── Graceful shutdown ──────────────────────────────────────────
            _ = &mut ctrl_c => {
                info!("Shutdown signal received. Draining connections...");
                let _ = shutdown_tx.send(());
                break;
            }
        }
    }

    Ok(())
}

// ── Pruner Thread Task ───────────────────────────────────────────────────
async fn start_pruner(db: Arc<redb::Database>, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
    // Random startup jitter 0-600s
    let jitter = rand::random::<u64>() % 600;
    tokio::time::sleep(std::time::Duration::from_secs(jitter)).await;

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let db_clone = db.clone();
                let pruned = tokio::task::spawn_blocking(move || prune_vault_sync(&db_clone))
                    .await
                    .unwrap_or(Ok(0))
                    .unwrap_or(0);
                info!(pruned_count = pruned, "TTL prune complete");
            }
            _ = shutdown.recv() => {
                info!("Pruner shutting down");
                break;
            }
        }
    }
}

fn prune_vault_sync(db: &redb::Database) -> anyhow::Result<u64> {
    let cutoff = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .saturating_sub(30 * 24 * 3600); // 30 days TTL

    let write_txn = db.begin_write()?;
    let mut pruned = 0;
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
            vault.remove(key.as_slice() as &[u8])?;
            pruned += 1;
        }
    }
    write_txn.commit()?;
    Ok(pruned)
}
