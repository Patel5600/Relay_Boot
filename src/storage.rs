use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use redb::{Database, TableDefinition, ReadableTable};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use tracing::{info, warn};
use tokio::sync::mpsc::UnboundedSender;

// Table definitions as specified in PRD Section 13.2 & 25
pub const VAULT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vault_v1");
pub const TOKENS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tokens_v1");
pub const SEQNO: TableDefinition<&[u8], u64> = TableDefinition::new("seqno_v1");

// Envelope limit parameters
pub const MAX_ENVELOPE_SIZE: usize = 64 * 1024; // 64 KB
pub const MAX_ENVELOPES_PER_RECIPIENT: usize = 500;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultEntry {
    pub stored_at: u64,    // Unix seconds — for TTL only
    pub payload: Vec<u8>,  // Encrypted blob — opaque to server
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlindedToken {
    pub blind_key: [u8; 32],       // SHA256(raw_token || server_secret)
    pub encrypted_token: Vec<u8>,  // Encrypted token payload
    pub expiry: u64,
}

pub struct WebhookTask {
    pub recipient_hash: [u8; 32],
}

pub struct RedbStorage {
    db: Arc<Database>,
}

impl RedbStorage {
    pub fn new(path: &str) -> Self {
        let db = match Database::create(path) {
            Ok(db) => Arc::new(db),
            Err(e) => {
                warn!("⚠️ Failed to open Redb database at '{}': {:?}. Attempting recovery by recreation...", path, e);
                // Self-healing recovery: rename corrupted file and create a fresh database
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let backup_path = format!("{}_corrupted_{}", path, now);
                let _ = std::fs::rename(path, &backup_path);
                let db = Database::create(path).expect("Critical: Failed to open fresh Redb database after recovery");
                Arc::new(db)
            }
        };

        // Initialize tables by starting and committing a write transaction
        {
            let write_txn = db.begin_write().expect("Failed to begin initialization write transaction");
            {
                let _ = write_txn.open_table(VAULT).expect("Failed to initialize VAULT table");
                let _ = write_txn.open_table(TOKENS).expect("Failed to initialize TOKENS table");
                let _ = write_txn.open_table(SEQNO).expect("Failed to initialize SEQNO table");
            }
            write_txn.commit().expect("Failed to commit database initialization transaction");
        }

        info!("Redb database initialized successfully at '{}'.", path);

        Self { db }
    }

    #[allow(dead_code)]
    pub fn new_from_db(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub fn get_db(&self) -> Arc<Database> {
        self.db.clone()
    }

    /// Stores an envelope in the Vault table atomically using a write transaction.
    pub async fn vault_store(
        &self,
        recipient_hash: [u8; 32],
        payload: Vec<u8>,
        webhook_tx: UnboundedSender<WebhookTask>,
    ) -> Result<crate::network::GlyphResponse, anyhow::Error> {
        // 1. Input validation
        if payload.len() > MAX_ENVELOPE_SIZE {
            return Ok(crate::network::GlyphResponse::Error { code: 413 });
        }
        if payload.len() < 32 { // Reject trivially small payloads (likely probes)
            return Ok(crate::network::GlyphResponse::Error { code: 400 });
        }

        let db = self.db.clone();

        // 2. Perform DB operations inside spawn_blocking (redb write txn is synchronous)
        let response = tokio::task::spawn_blocking(move || -> Result<crate::network::GlyphResponse, anyhow::Error> {
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
                if count >= MAX_ENVELOPES_PER_RECIPIENT {
                    return Ok(crate::network::GlyphResponse::Error { code: 507 });
                }

                // Get and increment sequence number
                let seq = seqno_table
                    .get(recipient_hash.as_ref() as &[u8])?
                    .map(|v| v.value())
                    .unwrap_or(0);
                let next_seq = seq + 1;
                seqno_table.insert(recipient_hash.as_ref() as &[u8], next_seq)?;

                // Build composite key: [32 bytes recipient_hash] ++ [8 bytes big-endian next_seq]
                let mut key = [0u8; 40];
                key[..32].copy_from_slice(&recipient_hash);
                key[32..].copy_from_slice(&next_seq.to_be_bytes());

                let entry = VaultEntry {
                    stored_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    payload,
                };
                let mut entry_bytes = Vec::new();
                ciborium::into_writer(&entry, &mut entry_bytes)?;

                vault.insert(key.as_ref() as &[u8], entry_bytes.as_slice() as &[u8])?;
            }
            write_txn.commit()?;
            Ok(crate::network::GlyphResponse::StoreAck { success: true })
        }).await??;

        // 3. Trigger webhook task asynchronously
        let _ = webhook_tx.send(WebhookTask { recipient_hash });

        Ok(response)
    }

    /// Fetches all envelopes for the authenticated caller and atomically deletes them.
    pub async fn vault_fetch(
        &self,
        recipient_pubkey: libp2p::identity::PublicKey,
    ) -> Result<crate::network::GlyphResponse, anyhow::Error> {
        let pubkey_bytes = recipient_pubkey.encode_protobuf();
        let recipient_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(&pubkey_bytes);
            hasher.finalize().into()
        };

        let db = self.db.clone();

        // Read and delete are bundled in a single write transaction to guarantee atomic delivery
        let payloads = tokio::task::spawn_blocking(move || -> Result<Vec<Vec<u8>>, anyhow::Error> {
            let write_txn = db.begin_write()?;
            let payloads = {
                let mut vault = write_txn.open_table(VAULT)?;
                let mut seqno_table = write_txn.open_table(SEQNO)?;

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

                let mut results = Vec::new();
                let mut keys_to_delete = Vec::new();
                for item in vault.range(prefix_start.as_ref()..=prefix_end.as_ref())? {
                    let (k, v) = item?;
                    let entry: VaultEntry = ciborium::from_reader(v.value())?;
                    results.push(entry.payload);
                    keys_to_delete.push(k.value().to_vec());
                }

                // Delete fetched envelopes and reset sequence number to 0
                for key in &keys_to_delete {
                    vault.remove(key.as_slice() as &[u8])?;
                }
                if !keys_to_delete.is_empty() {
                    seqno_table.insert(recipient_hash.as_ref() as &[u8], 0u64)?;
                }

                results
            };
            write_txn.commit()?;
            Ok(payloads)
        }).await??;

        Ok(crate::network::GlyphResponse::FetchResult { payloads })
    }

    /// Registers a blinded push token in the TOKENS table.
    pub async fn register_token(
        &self,
        recipient_hash: [u8; 32],
        blind_key: [u8; 32],
        encrypted_token: Vec<u8>,
        expiry: u64,
    ) -> Result<crate::network::GlyphResponse, anyhow::Error> {
        let db = self.db.clone();

        let success = tokio::task::spawn_blocking(move || -> Result<bool, anyhow::Error> {
            let write_txn = db.begin_write()?;
            {
                let mut tokens = write_txn.open_table(TOKENS)?;
                let token_entry = BlindedToken {
                    blind_key,
                    encrypted_token,
                    expiry,
                };
                let mut entry_bytes = Vec::new();
                ciborium::into_writer(&token_entry, &mut entry_bytes)?;
                
                // Write token keyed by the recipient hash
                tokens.insert(recipient_hash.as_ref() as &[u8], entry_bytes.as_slice() as &[u8])?;
            }
            write_txn.commit()?;
            Ok(true)
        }).await??;

        Ok(crate::network::GlyphResponse::RegisterTokenAck { success })
    }

    /// Fetches and removes the blinded push token for a given recipient.
    pub fn take_blinded_token(&self, recipient_hash: &[u8; 32]) -> Result<Option<BlindedToken>, anyhow::Error> {
        let write_txn = self.db.begin_write()?;
        let token_opt = {
            let mut tokens = write_txn.open_table(TOKENS)?;
            let res = match tokens.remove(recipient_hash.as_slice() as &[u8])? {
                Some(bytes) => {
                    let token: BlindedToken = ciborium::from_reader(bytes.value())?;
                    Some(token)
                }
                None => None,
            };
            res
        };
        write_txn.commit()?;
        Ok(token_opt)
    }
}
