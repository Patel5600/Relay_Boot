use libp2p::swarm::NetworkBehaviour;
use libp2p::{kad, relay, request_response, identify, ping, dcutr};
use serde::{Deserialize, Serialize};

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

// ── NetworkBehaviour ─────────────────────────────────────────────────────
#[derive(NetworkBehaviour)]
pub struct GlyphAnchorBehaviour {
    pub kad:              kad::Behaviour<kad::store::MemoryStore>,
    pub relay:            relay::Behaviour,
    pub dcutr:            dcutr::Behaviour,
    pub request_response: request_response::cbor::Behaviour<GlyphRequest, GlyphResponse>,
    pub identify:         identify::Behaviour,
    pub ping:             ping::Behaviour,
}
