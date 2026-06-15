use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use libp2p::{identity, Multiaddr, swarm::SwarmEvent, PeerId};
use futures::stream::StreamExt;
use futures::FutureExt;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod network;
mod storage;

use network::{GlyphAnchorBehaviour, GlyphAnchorBehaviourEvent, RequestEnvelope, ResponseEnvelope};
use storage::SledStorage;

pub fn load_or_generate_keypair(path: &str) -> identity::Keypair {
    let path = Path::new(path);
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

fn main() -> Result<(), Box<dyn Error>> {
    // Setup telemetry logger
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(32)
        .global_queue_interval(61) // Optimize thread-stealing frequency
        .build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn Error>> {

    info!("🌌 Initializing Glyph Hybrid Anchor Node...");

    // Setup static identity
    let keypair_path = ".glyph_identity";
    let local_key = load_or_generate_keypair(keypair_path);
    let local_peer_id = local_key.public().to_peer_id();
    info!("Static PeerId: {}", local_peer_id);

    // Initialize Sled Database & DashMap Cache
    let db_path = ".glyph_database";
    let storage = Arc::new(SledStorage::new(db_path));

    // Spawn the background Sled DB TTL & Cache Pruning task (every 1 hour, 30 days TTL)
    let storage_clone = storage.clone();
    tokio::spawn(async move {
        let prune_interval_secs = 3600; // 1 hour
        let ttl_secs = 30 * 24 * 3600; // 30 days
        loop {
            let storage_inner = storage_clone.clone();
            let result = std::panic::AssertUnwindSafe(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(prune_interval_secs));
                loop {
                    interval.tick().await;
                    if let Err(e) = storage_inner.prune_expired_records(ttl_secs) {
                        warn!("Database pruning task encountered error: {:?}", e);
                    }
                }
            }).catch_unwind().await;

            if let Err(err) = result {
                warn!("⚠️ Database pruning task panicked: {:?}. Restarting task in 5 seconds...", err);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    });

    // Build swarm using the type-safe fluent SwarmBuilder API in libp2p 0.54
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic_config(|mut config| {
            config.max_concurrent_stream_limit = 1000;
            config.max_stream_data = 32 * 1024 * 1024; // 32MB stream window
            config.max_connection_data = 64 * 1024 * 1024; // 64MB connection window
            config
        })
        .with_dns_config(
            libp2p::dns::ResolverConfig::cloudflare(),
            libp2p::dns::ResolverOpts::default(),
        )
        .with_behaviour(|keypair: &identity::Keypair| {
            let local_peer = keypair.public().to_peer_id();

            // 1. Kademlia DHT MemoryStore behaviour (Explicit Server Mode)
            let kad_config = libp2p::kad::Config::new(libp2p::StreamProtocol::new("/glyph/kad/1.0.0"));
            let store = libp2p::kad::store::MemoryStore::new(local_peer);
            let mut kademlia = libp2p::kad::Behaviour::with_config(local_peer, store, kad_config);
            kademlia.set_mode(Some(libp2p::kad::Mode::Server));

            // 2. Circuit Relay v2 server limits
            let mut relay_config = libp2p::relay::Config::default();
            relay_config.max_reservations = 1000;
            relay_config.max_circuits = 1000;
            relay_config.max_circuits_per_peer = 3;
            relay_config.reservation_duration = std::time::Duration::from_secs(120); // 2 minutes
            let relay = libp2p::relay::Behaviour::new(local_peer, relay_config);

            // 3. Request-Response (CBOR) offline cache protocol
            let mut req_resp_config = libp2p::request_response::Config::default();
            req_resp_config = req_resp_config.with_request_timeout(std::time::Duration::from_secs(10));
            let request_response = libp2p::request_response::cbor::Behaviour::new(
                [(libp2p::StreamProtocol::new("/glyph/req-resp/1.0.0"), libp2p::request_response::ProtocolSupport::Full)],
                req_resp_config,
            );

            // 4. Identify & Ping behaviors
            let identify_config = libp2p::identify::Config::new(
                "/glyph/1.0.0".to_string(),
                keypair.public(),
            );
            let identify = libp2p::identify::Behaviour::new(identify_config);
            let ping = libp2p::ping::Behaviour::default();

            // 5. DCUtR direct connection upgrade helper
            let dcutr = libp2p::dcutr::Behaviour::new(local_peer);

            GlyphAnchorBehaviour {
                kademlia,
                relay,
                request_response,
                identify,
                ping,
                dcutr,
            }
        })?
        .build();

    // Bind dual ports listening simultaneously
    let tcp_addr: Multiaddr = "/ip4/0.0.0.0/tcp/5678".parse()?;
    let quic_addr: Multiaddr = "/ip4/0.0.0.0/udp/5678/quic-v1".parse()?;
    
    swarm.listen_on(tcp_addr)?;
    swarm.listen_on(quic_addr)?;

    info!("Swarm dual-transports initialized. Listening on port 5678 (TCP & UDP/QUIC)...");

    // Track active connection counts per peer to defend against Sybil flooding
    let mut peer_connections = std::collections::HashMap::<PeerId, usize>::new();

    // Swarm event routing loop
    loop {
        // Retrieve next event, catching any panic in the network stream polling
        let event_opt = match std::panic::AssertUnwindSafe(swarm.next()).catch_unwind().await {
            Ok(evt) => evt,
            Err(e) => {
                warn!("⚠️ Swarm event polling panicked: {:?}. Attempting to recover...", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        let event = match event_opt {
            Some(evt) => evt,
            None => {
                info!("Swarm event stream terminated.");
                break;
            }
        };

        // Catch panics during individual event handling to prevent a single bad event from crashing the server
        // We wrap the closure in AssertUnwindSafe so all borrowed local variables (swarm, peer_connections) are treated as panic-safe.
        let handle_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {

            match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on Multiaddress: {}/p2p/{}", address, local_peer_id);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    let count = peer_connections.entry(peer_id).or_insert(0);
                    *count += 1;
                    if *count > 2 {
                        warn!("Peer {} exceeded concurrent connection limit ({}). Dropping connection...", peer_id, *count);
                        let _ = swarm.disconnect_peer_id(peer_id);
                    } else {
                        info!("Connection established with peer: {} (active links: {})", peer_id, *count);
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    let mut closed = false;
                    let mut remaining = 0;
                    if let Some(count) = peer_connections.get_mut(&peer_id) {
                        if *count > 0 {
                            *count -= 1;
                        }
                        remaining = *count;
                        if *count == 0 {
                            closed = true;
                        }
                    }
                    if closed {
                        peer_connections.remove(&peer_id);
                    }
                    info!("Connection closed with peer: {} (active links remaining: {})", peer_id, remaining);
                }
                SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                    GlyphAnchorBehaviourEvent::RequestResponse(libp2p::request_response::Event::Message { message, .. }) => {
                        if let libp2p::request_response::Message::Request { request, channel, .. } = message {
                            match request {
                                RequestEnvelope::QueryUsername { username } => {
                                    let available = storage.is_username_available(&username);
                                    let owner_pub_key = if !available {
                                        storage.get_username_owner(&username)
                                    } else {
                                        None
                                    };
                                    let response = ResponseEnvelope::UsernameStatus { available, owner_pub_key };
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
                                }
                                RequestEnvelope::RegisterUsername { username, public_key } => {
                                    match storage.register_username_first_write_wins(&username, &public_key) {
                                        Ok(true) => {
                                            info!("Successfully registered unique username: @{}", username);
                                            // Broadcast key mapping to the Kademlia DHT
                                            let key = libp2p::kad::RecordKey::new(&SledStorage::hash_username(&username));
                                            let record = libp2p::kad::Record {
                                                key,
                                                value: public_key,
                                                publisher: None,
                                                expires: None,
                                            };
                                            if let Err(e) = swarm.behaviour_mut().kademlia.put_record(record, libp2p::kad::Quorum::One) {
                                                warn!("Failed to publish record to Kademlia DHT: {:?}", e);
                                            }
                                            let response = ResponseEnvelope::RegistrationResult {
                                                success: true,
                                                message: "Username successfully minted".to_string(),
                                            };
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
                                        }
                                        Ok(false) => {
                                            warn!("Registration failed: Username @{} is already taken.", username);
                                            let response = ResponseEnvelope::RegistrationResult {
                                                success: false,
                                                message: "Username not available".to_string(),
                                            };
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
                                        }
                                        Err(e) => {
                                            warn!("Database error during registration of @{}: {:?}", username, e);
                                            let response = ResponseEnvelope::RegistrationResult {
                                                success: false,
                                                message: format!("Database transaction error: {}", e),
                                            };
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
                                        }
                                    }
                                }
                                RequestEnvelope::Store(envelope) => {
                                    info!("Storing blind offline envelope for pubkey hash: {:?}", &envelope.target_pub_key[..std::cmp::min(8, envelope.target_pub_key.len())]);
                                    match storage.store_envelope(envelope) {
                                        Ok(()) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, ResponseEnvelope::Stored);
                                        }
                                        Err(e) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, ResponseEnvelope::Error(e.to_string()));
                                        }
                                    }
                                }
                                RequestEnvelope::Fetch { target_pub_key } => {
                                    info!("Fetching offline envelopes for pubkey: {:?}", &target_pub_key[..std::cmp::min(8, target_pub_key.len())]);
                                    match storage.fetch_envelopes(&target_pub_key) {
                                        Ok(envelopes) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, ResponseEnvelope::Fetched(envelopes));
                                        }
                                        Err(e) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, ResponseEnvelope::Error(e.to_string()));
                                        }
                                    }
                                }
                                RequestEnvelope::AcknowledgeDelivery { target_pub_key } => {
                                    info!("Acknowledging delivery and wiping offline envelopes for pubkey: {:?}", &target_pub_key[..std::cmp::min(8, target_pub_key.len())]);
                                    match storage.wipe_envelopes(&target_pub_key) {
                                        Ok(()) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, ResponseEnvelope::Stored);
                                        }
                                        Err(e) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, ResponseEnvelope::Error(e.to_string()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    GlyphAnchorBehaviourEvent::Kademlia(kad_event) => {
                        info!("Kademlia DHT Event: {:?}", kad_event);
                    }
                    GlyphAnchorBehaviourEvent::Relay(relay_event) => {
                        info!("Circuit Relay v2 Event: {:?}", relay_event);
                    }
                    GlyphAnchorBehaviourEvent::Identify(identify_event) => {
                        info!("Identify Event: {:?}", identify_event);
                        if let libp2p::identify::Event::Received { peer_id, info, .. } = identify_event {
                            // Dynamically register observed addresses into Kademlia DHT routing table
                            for addr in info.listen_addrs {
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                            }
                        }
                    }
                    GlyphAnchorBehaviourEvent::Ping(ping_event) => {
                        if let libp2p::ping::Event { peer, result: Ok(rtt), .. } = ping_event {
                            info!("Liveness ping with peer {} returned RTT: {:?}", peer, rtt);
                        }
                    }
                    GlyphAnchorBehaviourEvent::Dcutr(dcutr_event) => {
                        info!("DCUtR Hole Punching Event: {:?}", dcutr_event);
                    }
                    _ => {}
                }
                _ => {}
            }
        }));

        if let Err(panic_err) = handle_result {
            warn!("⚠️ Critical: Panicked while processing Swarm event: {:?}", panic_err);
        }
    }

    Ok(())
}
