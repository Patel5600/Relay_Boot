use std::sync::Arc;
use dashmap::DashMap;
use sled::{Db, Tree};
use sled::transaction::TransactionError;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use tracing::{info, warn};
use reqwest::Client;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRecord {
    pub public_key: Vec<u8>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    pub envelope: crate::network::OfflineEnvelope,
    pub created_at: u64,
}

pub struct SledStorage {
    #[allow(dead_code)]
    db: Db,
    username_registry: Tree,
    offline_vault: Tree,
    // Sharded lock-free map caching Username Hash -> Public Key bytes
    pub username_cache: Arc<DashMap<Vec<u8>, Vec<u8>>>,
    // HTTP client for push notifications
    http_client: Client,
}

impl SledStorage {
    pub fn new(path: &str) -> Self {
        let config = sled::Config::default()
            .path(path)
            .cache_capacity(512 * 1024 * 1024) // 512MB RAM cache layer
            .flush_every_ms(Some(50))           // Asynchronous background flush every 50ms
            .use_compression(false);            // Prioritize speed over disk compression

        let db = match config.open() {
            Ok(db) => db,
            Err(e) => {
                warn!("⚠️ Failed to open Sled database at '{}': {:?}. Attempting self-healing recovery...", path, e);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let backup_path = format!("{}_corrupted_{}", path, now);
                if let Err(rename_err) = std::fs::rename(path, &backup_path) {
                    warn!("⚠️ Failed to rename corrupted database directory: {:?}. Attempting deletion...", rename_err);
                    let _ = std::fs::remove_dir_all(path);
                } else {
                    info!("📁 Corrupted database directory renamed to '{}' for recovery.", backup_path);
                }
                config.open().expect("Critical: Failed to open fresh Sled database after self-healing recovery")
            }
        };

        let username_registry = db.open_tree("username_registry").unwrap_or_else(|e| {
            warn!("⚠️ Failed to open username_registry tree: {:?}. Clearing tree...", e);
            let _ = db.drop_tree("username_registry");
            db.open_tree("username_registry").expect("Critical: Failed to recreate username_registry tree")
        });

        let offline_vault = db.open_tree("offline_vault").unwrap_or_else(|e| {
            warn!("⚠️ Failed to open offline_vault tree: {:?}. Clearing tree...", e);
            let _ = db.drop_tree("offline_vault");
            db.open_tree("offline_vault").expect("Critical: Failed to recreate offline_vault tree")
        });
        
        let username_cache = Arc::new(DashMap::new());
        
        // Hydrate DashMap cache from Sled DB on startup for gaming-speed lookup
        for item in username_registry.iter() {
            if let Ok((key, val)) = item {
                if let Ok(record) = serde_json::from_slice::<RegistryRecord>(&val) {
                    username_cache.insert(key.to_vec(), record.public_key);
                }
            }
        }
        
        info!("Sled database loaded. Cache hydrated with {} names.", username_cache.len());
        
        Self {
            db,
            username_registry,
            offline_vault,
            username_cache,
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Computes the unique SHA-256 hash of a username for routing keys.
    pub fn hash_username(username: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(username.to_lowercase().trim().as_bytes());
        hasher.finalize().to_vec()
    }

    /// Checks lookup cache for username availability.
    pub fn is_username_available(&self, username: &str) -> bool {
        let hash = Self::hash_username(username);
        !self.username_cache.contains_key(&hash)
    }

    /// Returns the owner public key bytes for a registered username.
    pub fn get_username_owner(&self, username: &str) -> Option<Vec<u8>> {
        let hash = Self::hash_username(username);
        self.username_cache.get(&hash).map(|ref_val| ref_val.value().clone())
    }

    /// Implements First-Write-Wins registry using Sled transaction/compare_and_swap.
    pub fn register_username_first_write_wins(&self, username: &str, public_key: &[u8]) -> Result<bool, sled::Error> {
        let hash = Self::hash_username(username);
        
        // Fast-path: Check DashMap hot-cache first
        if self.username_cache.contains_key(&hash) {
            return Ok(false);
        }

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = RegistryRecord {
            public_key: public_key.to_vec(),
            created_at,
        };
        let serialized = serde_json::to_vec(&record).unwrap();

        // Slow-path: Enforce transactionally in Sled DB
        let result = self.username_registry.transaction(|tx_db| {
            if tx_db.get(hash.as_slice())?.is_some() {
                Ok::<bool, sled::transaction::ConflictableTransactionError<()>>(false)
            } else {
                tx_db.insert(hash.as_slice(), serialized.as_slice())?;
                Ok::<bool, sled::transaction::ConflictableTransactionError<()>>(true)
            }
        }).map_err(|e: TransactionError<()>| match e {
            TransactionError::Storage(err) => err,
            TransactionError::Abort(()) => sled::Error::Unsupported("Transaction aborted".to_string()),
        })?;

        if result {
            // Update hot-cache
            self.username_cache.insert(hash, public_key.to_vec());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Stores an envelope in the Sled database for store-and-forward caching.
    pub fn store_envelope(&self, envelope: crate::network::OfflineEnvelope) -> Result<(), sled::Error> {
        let target_pub_key = envelope.target_pub_key.clone();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let record = VaultRecord {
            envelope,
            created_at,
        };

        self.offline_vault.transaction(|tx_db| {
            let mut list = if let Some(existing) = tx_db.get(target_pub_key.as_slice())? {
                serde_json::from_slice::<Vec<VaultRecord>>(&existing).unwrap_or_default()
            } else {
                Vec::new()
            };
            list.push(record.clone());
            let serialized = serde_json::to_vec(&list).unwrap();
            tx_db.insert(target_pub_key.as_slice(), serialized.as_slice())?;
            Ok::<(), sled::transaction::ConflictableTransactionError<()>>(())
        }).map_err(|e: TransactionError<()>| match e {
            TransactionError::Storage(err) => err,
            TransactionError::Abort(()) => sled::Error::Unsupported("Transaction aborted".to_string()),
        })?;

        // Trigger push notification if token exists
        if let Some(ref token) = record.envelope.push_token {
            self.trigger_blind_push(token);
        }

        Ok(())
    }

    /// Fetches pending envelopes for a target public key (does NOT wipe them).
    pub fn fetch_envelopes(&self, target_pub_key: &[u8]) -> Result<Vec<crate::network::OfflineEnvelope>, sled::Error> {
        let result = self.offline_vault.get(target_pub_key)?;
        if let Some(bytes) = result {
            if let Ok(records) = serde_json::from_slice::<Vec<VaultRecord>>(&bytes) {
                let envelopes = records.into_iter().map(|r| r.envelope).collect();
                return Ok(envelopes);
            }
        }
        Ok(Vec::new())
    }

    /// Deletes (wipes) all pending envelopes for a target public key.
    pub fn wipe_envelopes(&self, target_pub_key: &[u8]) -> Result<(), sled::Error> {
        self.offline_vault.remove(target_pub_key)?;
        Ok(())
    }

    /// Triggers push webhook gateway asynchronously using reqwest
    pub fn trigger_blind_push(&self, push_token: &str) {
        let client = self.http_client.clone();
        let token = push_token.to_string();
        tokio::spawn(async move {
            info!("Firing blind push webhook to UnifiedPush/Firebase gateway for token: {}", token);
            let payload = serde_json::json!({
                "to": token,
                "data": {
                    "alert": "New blind envelope waiting",
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                }
            });
            let gateway_url = "https://gateway.unifiedpush.org/send";
            match client.post(gateway_url).json(&payload).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        info!("Push notification request successfully dispatched.");
                    } else {
                        warn!("Push gateway returned failure: {:?}", resp.status());
                    }
                }
                Err(e) => {
                    warn!("Failed to dispatch push notification: {:?}", e);
                }
            }
        });
    }

    /// Prunes stale username registry and offline message vault entries exceeding TTL
    pub fn prune_expired_records(&self, ttl_secs: u64) -> Result<(), sled::Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut registry_removed = 0;
        let mut vault_removed = 0;

        for item in self.username_registry.iter() {
            if let Ok((key, val)) = item {
                if let Ok(record) = serde_json::from_slice::<RegistryRecord>(&val) {
                    if now - record.created_at > ttl_secs {
                        self.username_registry.remove(&key)?;
                        self.username_cache.remove(key.as_ref());
                        registry_removed += 1;
                    }
                }
            }
        }

        for item in self.offline_vault.iter() {
            if let Ok((key, val)) = item {
                if let Ok(mut records) = serde_json::from_slice::<Vec<VaultRecord>>(&val) {
                    let original_len = records.len();
                    records.retain(|r| now - r.created_at <= ttl_secs);
                    if records.len() != original_len {
                        if records.is_empty() {
                            self.offline_vault.remove(&key)?;
                        } else {
                            let new_val = serde_json::to_vec(&records).unwrap();
                            self.offline_vault.insert(&key, new_val)?;
                        }
                        vault_removed += original_len - records.len();
                    }
                }
            }
        }

        if registry_removed > 0 || vault_removed > 0 {
            info!("Pruning finished: removed {} stale registry names and {} expired messages.", registry_removed, vault_removed);
        }

        Ok(())
    }
}
