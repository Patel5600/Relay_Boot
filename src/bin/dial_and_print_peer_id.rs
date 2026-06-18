use std::error::Error;
use std::time::Duration;
use libp2p::{identity, swarm::SwarmEvent, SwarmBuilder, Multiaddr};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_| {
            libp2p::ping::Behaviour::default()
        })?
        .build();

    let target_addr: Multiaddr = "/ip4/127.0.0.1/tcp/5678".parse()?;
    println!("Dialing {}...", target_addr);
    swarm.dial(target_addr)?;

    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        println!("SUCCESS! Connected to peer: {}", peer_id);
                        println!("Endpoint: {:?}", endpoint);
                        return Ok(());
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        println!("Failed to connect: peer={:?}, error={:?}", peer_id, error);
                        return Ok(());
                    }
                    _ => {}
                }
            }
            _ = &mut timeout => {
                println!("Timeout waiting for connection");
                return Ok(());
            }
        }
    }
}
