use std::error::Error;
use std::fs;
use std::path::Path;
use libp2p::identity;

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
        fs::write(path, bytes).expect("Failed to write keypair file");
        keypair
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let keypair = load_or_generate_keypair(".glyph_identity");
    let peer_id = keypair.public().to_peer_id();
    println!("PEER_ID: {}", peer_id);
    
    // Also print PEER_ID for zero seed just in case
    let mut seed = [0u8; 32];
    let secret_key = identity::ed25519::SecretKey::try_from_bytes(&mut seed).unwrap();
    let zero_keypair = identity::Keypair::from(identity::ed25519::Keypair::from(secret_key));
    println!("ZERO_SEED_PEER_ID: {}", zero_keypair.public().to_peer_id());
    Ok(())
}
