use libp2p::swarm::NetworkBehaviour;
use libp2p::{kad, relay, request_response, identify, ping, dcutr};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineEnvelope {
    pub target_pub_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub push_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestEnvelope {
    Store(OfflineEnvelope),
    Fetch { target_pub_key: Vec<u8> },
    QueryUsername { username: String },
    RegisterUsername { username: String, public_key: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseEnvelope {
    Stored,
    Fetched(Vec<OfflineEnvelope>),
    UsernameStatus { available: bool, owner_pub_key: Option<Vec<u8>> },
    RegistrationResult { success: bool, message: String },
    Error(String),
}

#[derive(NetworkBehaviour)]
pub struct GlyphAnchorBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub relay: relay::Behaviour,
    pub request_response: request_response::cbor::Behaviour<RequestEnvelope, ResponseEnvelope>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub dcutr: dcutr::Behaviour,
}
