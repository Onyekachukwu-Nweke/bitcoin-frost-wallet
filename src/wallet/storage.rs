use crate::common::errors::{FrostWalletError, Result};
use crate::wallet::transaction::Utxo;
use bitcoin::{Address, Network, Transaction, Txid};
use frost_secp256k1::{keys::PublicKeyPackage, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Wallet state storage
#[derive(Clone)]
pub struct WalletStorage {
    /// Storage path
    path: PathBuf,
    /// In-memory cache of wallet state (thread-safe)
    state: Arc<Mutex<WalletState>>,
}

/// Wallet state data structure
#[derive(Debug, Serialize, Deserialize, Default)]
struct WalletState {
    /// Wallet addresses
    addresses: Vec<Address>,
    /// Available UTXOs
    utxos: Vec<Utxo>,
    /// Unsigned transactions (txid -> utxos)
    unsigned_txs: HashMap<Txid, Vec<Utxo>>,
    /// Signed transactions
    signed_txs: HashSet<Txid>,
    /// FROST public key
    frost_public_key: Option<Vec<u8>>,
}

impl WalletStorage {
    /// Create a new wallet storage instance
    pub fn new(path: PathBuf) -> Result<Self> {
        // Create directory if it doesn't exist
        if !path.exists() {
            fs::create_dir_all(&path)
                .map_err(|e| FrostWalletError::IoError(e))?;
        }

        // Initialize state
        let state = if let Ok(state) = Self::load_state(&path) {
            state
        } else {
            WalletState::default()
        };

        let storage = Self {
            path,
            state: Arc::new(Mutex::new(state)),
        };

        Ok(storage)
    }

    /// Save FROST public key
    pub fn save_frost_public_key(&self, public_key: &PublicKeyPackage) -> Result<()> {
        let verifying_key = public_key.verifying_key();
        let key_bytes = verifying_key.serialize().unwrap();

        let mut state = self.state.lock().unwrap();
        state.frost_public_key = Some(key_bytes.to_vec());

        self.save_state(&state)
    }

    /// Get FROST public key
    // Tentative
    pub fn get_frost_public_key(&self) -> Result<VerifyingKey> {
        let state = self.state.lock().unwrap();

        if let Some(key_bytes) = &state.frost_public_key {
            VerifyingKey::try_from(key_bytes.as_slice())
                .map_err(|e| FrostWalletError::FrostError(format!("Invalid public key: {:?}", e)))
        } else {
            Err(FrostWalletError::InvalidState("No FROST public key available".to_string()))
        }
    }

    /// Save a new address
    pub fn save_address(&self, address: &Address) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        if !state.addresses.contains(address) {
            state.addresses.push(address.clone());
            self.save_state(&state)?;
        }

        Ok(())
    }

    /// Get all wallet addresses
    pub fn get_addresses(&self) -> Result<Vec<Address>> {
        let state = self.state.lock().unwrap();
        Ok(state.addresses.clone())
    }

    /// Add a new UTXO
    pub fn add_utxo(&self, utxo: Utxo) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        // Check if UTXO already exists
        if !state.utxos.iter().any(|u| u.txid == utxo.txid && u.vout == utxo.vout) {
            state.utxos.push(utxo);
            self.save_state(&state)?;
        }

        Ok(())
    }

    /// Remove a spent UTXO
    pub fn remove_utxo(&self, txid: &Txid, vout: u32) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        state.utxos.retain(|u| !(u.txid == *txid && u.vout == vout));
        self.save_state(&state)?;

        Ok(())
    }

    /// Get all available UTXOs
    pub fn get_utxos(&self) -> Result<Vec<Utxo>> {
        let state = self.state.lock().unwrap();
        Ok(state.utxos.clone())
    }

    /// Save an unsigned transaction with its selected UTXOs
    pub fn save_unsigned_tx(&self, tx: &Transaction, utxos: &[Utxo]) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        let txid = tx.txid();
        state.unsigned_txs.insert(txid, utxos.to_vec());
        self.save_state(&state)?;

        Ok(())
    }

    /// Get UTXOs for a specific transaction
    pub fn get_utxos_for_tx(&self, tx: &Transaction) -> Result<Vec<Utxo>> {
        let state = self.state.lock().unwrap();

        let txid = tx.txid();
        if let Some(utxos) = state.unsigned_txs.get(&txid) {
            Ok(utxos.clone())
        } else {
            Err(FrostWalletError::InvalidState(format!("No UTXOs found for transaction {}", txid)))
        }
    }

    /// Save a signed transaction
    pub fn save_signed_tx(&self, tx: &Transaction) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        let txid = tx.txid();

        // Mark transaction as signed
        state.signed_txs.insert(txid);

        // If this transaction was using any UTXOs, mark them as spent
        if let Some(utxos) = state.unsigned_txs.remove(&txid) {
            // Remove spent UTXOs from available UTXOs
            for utxo in &utxos {
                state.utxos.retain(|u| !(u.txid == utxo.txid && u.vout == utxo.vout));
            }
        }

        self.save_state(&state)?;

        Ok(())
    }

    /// Check if a transaction is signed
    pub fn is_signed(&self, txid: &Txid) -> Result<bool> {
        let state = self.state.lock().unwrap();
        Ok(state.signed_txs.contains(txid))
    }

    /// Load wallet state from disk
    fn load_state(path: &Path) -> Result<WalletState> {
        let state_path = path.join("wallet_state.json");

        if !state_path.exists() {
            return Ok(WalletState::default());
        }

        let file = File::open(&state_path)
            .map_err(|e| FrostWalletError::IoError(e))?;

        let reader = BufReader::new(file);
        let state: WalletState = serde_json::from_reader(reader)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to parse wallet state: {}", e)))?;

        Ok(state)
    }

    /// Save wallet state to disk
    fn save_state(&self, state: &WalletState) -> Result<()> {
        let state_path = self.path.join("wallet_state.json");

        let file = File::create(&state_path)
            .map_err(|e| FrostWalletError::IoError(e))?;

        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, state)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize wallet state: {}", e)))?;

        Ok(())
    }

    /// Sync with the blockchain by adding new UTXOs and removing spent ones
    /// This would be called when the wallet connects to the Bitcoin node
    pub fn sync_with_blockchain(&self, new_utxos: Vec<Utxo>, spent_outpoints: Vec<(Txid, u32)>) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        // Add new UTXOs
        for utxo in new_utxos {
            if !state.utxos.iter().any(|u| u.txid == utxo.txid && u.vout == utxo.vout) {
                state.utxos.push(utxo);
            }
        }

        // Remove spent UTXOs
        for (txid, vout) in spent_outpoints {
            state.utxos.retain(|u| !(u.txid == txid && u.vout == vout));
        }

        self.save_state(&state)?;

        Ok(())
    }
}