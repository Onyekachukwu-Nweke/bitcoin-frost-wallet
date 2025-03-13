use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{WalletConfig, ThresholdConfig};
use crate::frost_dkg::chilldkg::DkgCoordinator;
use crate::frost_dkg::dkg_process::DkgProcessController;
use crate::frost_dkg::frost::FrostCoordinator;
use crate::frost_dkg::signing_process::SigningProcessController;

use bitcoin::{
    Address, Network, ScriptBuf, Transaction,
    TxIn, TxOut, OutPoint, consensus::encode::serialize_hex,
    sighash::TapSighash, Amount, hashes::Hash, psbt::Psbt,
    secp256k1::{Secp256k1, XOnlyPublicKey, Message}, Txid,
    transaction, Sequence, Witness, TapSighashType
};
use frost_secp256k1::{
    Identifier, Signature,
    keys::{KeyPackage, PublicKeyPackage},
};
use rand_core::OsRng;
use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode;
use bitcoin::sighash::{Prevouts, SighashCache};
use tokio::sync::Mutex;
use crate::rpc::rpc::{BitcoinRpcClient, Utxo};

/// Bitcoin FROST Wallet implementation
pub struct BitcoinFrostWallet {
    /// Wallet configuration
    config: WalletConfig,
    /// Local participant ID
    local_id: Identifier,
    /// Local key package
    key_package: Option<KeyPackage>,
    /// Group public key package
    pub_key_package: Option<PublicKeyPackage>,
    /// Wallet storage path
    storage_path: PathBuf,
    /// Bitcoin network (mainnet, testnet, regtest)
    network: Network,
    /// UTXO set
    utxos: Vec<WalletUtxo>,
    /// Transaction history
    transactions: Vec<WalletTransaction>,
    /// DKG process controller
    dkg_controller: Option<DkgProcessController>,
    /// Signing process controller
    signing_controller: Option<SigningProcessController>,
    /// Bitcoin RPC client
    rpc_client: Option<Arc<dyn BitcoinRpcClient>>,
}

/// UTXO representation for the wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Script pubkey
    pub script_pubkey: Vec<u8>,
    /// Confirmation status
    pub confirmed: bool,
    /// Block height where this UTXO was confirmed (if any)
    pub block_height: Option<u32>,
}

/// Transaction representation for the wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransaction {
    /// Transaction ID
    pub txid: String,
    /// Raw transaction hex
    pub raw_tx: String,
    /// Amount transferred (negative for outgoing)
    pub amount: i64,
    /// Fee paid
    pub fee: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Confirmation status
    pub confirmed: bool,
    /// Block height where this transaction was confirmed (if any)
    pub block_height: Option<u32>,
}

/// Wallet balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    /// Confirmed balance in satoshis
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis
    pub unconfirmed: u64,
    /// Total balance (confirmed + unconfirmed)
    pub total: u64,
}

impl BitcoinFrostWallet {
    /// Create a new Bitcoin FROST wallet with the given configuration
    pub fn new(
        local_id: Identifier,
        config: WalletConfig,
        storage_path: impl AsRef<Path>
    ) -> Self {
        let storage_path = storage_path.as_ref().to_path_buf();

        Self {
            config: config.clone(),
            local_id,
            key_package: None,
            pub_key_package: None,
            storage_path,
            network: config.network,
            utxos: Vec::new(),
            transactions: Vec::new(),
            dkg_controller: None,
            signing_controller: None,
            rpc_client: None,
        }
    }

    /// Connect to Bitcoin node using RPC
    pub fn connect_to_node(&mut self, rpc_client: Arc<dyn BitcoinRpcClient>) {
        self.rpc_client = Some(rpc_client);
    }

    /// Initialize the wallet
    pub async fn initialize(&mut self) -> Result<()> {
        // Create storage directory if it doesn't exist
        if !self.storage_path.exists() {
            fs::create_dir_all(&self.storage_path)
                .map_err(|e| FrostWalletError::IoError(e))?;
        }

        // Try to load wallet state
        match self.load_state() {
            Ok(_) => {
                // Wallet state loaded successfully
                log::info!("Wallet state loaded successfully");

                // If we have an RPC client and a wallet address, register it with the node
                if let (Some(rpc_client), Ok(address)) = (&self.rpc_client, self.get_address()) {
                    log::info!("Registering wallet address with Bitcoin node: {}", address);
                    let address_str = address.to_string();
                    rpc_client.import_address(&address_str, Some("frost-wallet"), false).await?;
                }

                return Ok(());
            },
            Err(e) => {
                log::warn!("Failed to load wallet state: {}", e);
                // Continue with initialization
            }
        }

        // Initialize an empty wallet
        self.utxos.clear();
        self.transactions.clear();

        Ok(())
    }

    /// Run distributed key generation (DKG)
    pub async fn run_dkg(
        &mut self,
        binary_path: PathBuf,
        socket_path: PathBuf
    ) -> Result<()> {
        // Create DKG controller
        let mut controller = DkgProcessController::new(
            self.local_id,
            self.config.threshold.clone(),
            binary_path
        );

        // Start IPC server
        controller.start_server(&socket_path).await?;

        // Run DKG
        let key_package = controller.run_dkg().await?;

        // Get public key package
        let pub_key_package = controller.coordinator.get_public_key_package()?;

        // Store key packages
        self.key_package = Some(key_package);
        self.pub_key_package = Some(pub_key_package);

        // Update wallet config
        self.config.public_key_package = self.pub_key_package.clone();

        // Save wallet state
        self.save_state()?;

        // Store controller for later use
        self.dkg_controller = Some(controller);

        // If we have an RPC client, register the wallet address with the Bitcoin node
        if let Some(rpc_client) = &self.rpc_client {
            let address = self.get_address()?;
            log::info!("Registering wallet address with Bitcoin node: {}", address);
            let address_str = address.to_string();
            rpc_client.import_address(&address_str, Some("frost-wallet"), false).await?;
        }

        Ok(())
    }

    /// Get the wallet address
    pub fn get_address(&self) -> Result<Address> {
        let pub_key_package = self.pub_key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No public key package".to_string()))?;

        // Get the Schnorr public key from the public key package
        let verifying_key = pub_key_package.verifying_key();

        // Convert to Bitcoin secp256k1 format
        let secp = bitcoin::secp256k1::Secp256k1::new();

        // We need to get the raw bytes of the verifying key
        // frost_secp256k1 doesn't have a direct to_bytes() method, so we serialize and extract the key bytes
        let pk_bytes: Vec<u8> = verifying_key.serialize().unwrap().to_vec();

        // Create XOnly public key for Taproot address
        let xonly_pubkey = XOnlyPublicKey::from_slice(&pk_bytes)
            .map_err(|e| FrostWalletError::InvalidState(format!("Invalid public key: {}", e)))?;

        // Create P2TR (Taproot) address
        let address = Address::p2tr(&secp, xonly_pubkey, None, self.network);

        Ok(address)
    }

    /// Sync wallet UTXOs from the Bitcoin node
    pub async fn sync_utxos(&mut self) -> Result<()> {
        // Ensure we have an RPC client
        let rpc_client = self.rpc_client.as_ref()
            .ok_or_else(|| FrostWalletError::ConnectionError("Not connected to Bitcoin node".to_string()))?;

        // Get our wallet address
        let address = self.get_address()?;
        let address_str = address.to_string();

        // Get UTXOs from the Bitcoin node
        let utxos = rpc_client.get_utxos(Some(1), None).await?;

        // Filter to only include UTXOs for our address
        let our_utxos: Vec<Utxo> = utxos.into_iter()
            .filter(|utxo| utxo.address == address_str)
            .collect();

        // Clear existing UTXOs and add the new ones
        self.utxos.clear();

        for utxo in our_utxos {
            let script_pubkey_bytes = hex::decode(&utxo.script_pub_key)
                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to decode script_pub_key: {}", e)))?;

            self.utxos.push(WalletUtxo {
                txid: utxo.txid.clone(),
                vout: utxo.vout,
                amount: utxo.amount.to_sat(),
                script_pubkey: script_pubkey_bytes,
                confirmed: utxo.confirmations > 0,
                block_height: if utxo.confirmations > 0 {
                    // We could get the exact block height from the RPC client, but for simplicity we'll use None
                    None
                } else {
                    None
                },
            });
        }

        // Save wallet state
        self.save_state()?;

        log::info!("Synced {} UTXOs from Bitcoin node", self.utxos.len());

        Ok(())
    }

    /// Create a Bitcoin transaction
    pub async fn create_transaction(
        &mut self,
        recipient: &str,
        amount: u64,
        fee_rate: f64
    ) -> Result<Transaction> {
        // Check if wallet is initialized
        if self.key_package.is_none() || self.pub_key_package.is_none() {
            return Err(FrostWalletError::InvalidState("Wallet not initialized".to_string()));
        }

        // Sync UTXOs first to ensure we have the latest state
        if let Some(rpc_client) = &self.rpc_client {
            self.sync_utxos().await?;
        }

        // Parse recipient address and make sure it's for the correct network
        let recipient_address = Address::from_str(recipient)
            .map_err(|_| FrostWalletError::InvalidState(format!("Invalid address: {}", recipient)))?
            .require_network(self.network)
            .map_err(|addr| FrostWalletError::InvalidState(
                format!("Address network mismatch: got {:?}, expected {:?}",
                        addr, self.network)
            ))?;

        // Get confirmed UTXOs
        let confirmed_utxos: Vec<&WalletUtxo> = self.utxos.iter()
            .filter(|utxo| utxo.confirmed)
            .collect();

        if confirmed_utxos.is_empty() {
            return Err(FrostWalletError::InvalidState("No confirmed UTXOs available".to_string()));
        }

        // Calculate total available amount
        let total_available: u64 = confirmed_utxos.iter()
            .map(|utxo| utxo.amount)
            .sum();

        // Estimate transaction size
        let estimated_size = 250; // Simplified estimate for a typical transaction

        // Calculate fee
        let fee = (fee_rate * estimated_size as f64 / 1000.0) as u64;

        // Check if we have enough funds
        if total_available < amount + fee {
            return Err(FrostWalletError::InsufficientFunds(
                format!("Insufficient funds: have {}, need {}",
                        Amount::from_sat(total_available),
                        Amount::from_sat(amount + fee))
            ));
        }

        // Coin selection (simple strategy: use UTXOs until we have enough)
        let mut selected_utxos = Vec::new();
        let mut selected_amount = 0;

        for utxo in confirmed_utxos {
            selected_utxos.push(utxo);
            selected_amount += utxo.amount;

            if selected_amount >= amount + fee {
                break;
            }
        }

        // Create transaction inputs
        let inputs: Vec<TxIn> = selected_utxos.iter()
            .map(|utxo| {
                let txid = Txid::from_str(&utxo.txid)
                    .expect("Invalid txid format");
                let outpoint = OutPoint::new(txid, utxo.vout);
                TxIn {
                    previous_output: outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(0xFFFFFFFF),
                    witness: Witness::new(),
                }
            })
            .collect();

        // Create transaction outputs
        let mut outputs = Vec::new();

        // Payment output
        outputs.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: recipient_address.script_pubkey(),
        });

        // Change output (if any)
        let change_amount = selected_amount - amount - fee;
        if change_amount > 0 {
            let change_address = self.get_address()?;
            outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: change_address.script_pubkey(),
            });
        }

        // Create transaction
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // Add transaction to history (as unsigned)
        let tx_hex = encode::serialize_hex(&tx);
        let wallet_tx = WalletTransaction {
            txid: tx.txid().to_string(),
            raw_tx: tx_hex,
            amount: -(amount as i64), // Negative for outgoing
            fee: fee,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            confirmed: false,
            block_height: None,
        };
        self.add_transaction(wallet_tx)?;

        Ok(tx)
    }

    /// Sign a transaction using FROST
    pub async fn sign_transaction(
        &mut self,
        tx: &Transaction,
        signers: Vec<Identifier>
    ) -> Result<Transaction> {
        // Initialize signing controller if not already initialized
        if self.signing_controller.is_none() {
            let mut controller = SigningProcessController::new(
                self.local_id,
                self.config.threshold.clone(),
            );

            // Set key packages
            controller.set_key_package(
                self.key_package.clone().ok_or_else(||
                    FrostWalletError::InvalidState("No key package".to_string()))?,
                self.pub_key_package.clone().ok_or_else(||
                    FrostWalletError::InvalidState("No public key package".to_string()))?
            )?;

            self.signing_controller = Some(controller);
        }

        let controller = self.signing_controller.as_mut().unwrap();

        // Create a PSBT for this transaction
        let mut psbt = Psbt::from_unsigned_tx(tx.clone())
            .map_err(|e| FrostWalletError::InvalidState(
                format!("Failed to create PSBT: {}", e)))?;

        // Collect all previous outputs (UTXOs) for Prevouts
        let mut prevouts = Vec::new();
        for input in tx.input.iter() {
            let utxo = self.utxos.iter()
                .find(|u| {
                    let txid = Txid::from_str(&u.txid).expect("Invalid txid format");
                    txid == input.previous_output.txid && u.vout == input.previous_output.vout
                })
                .ok_or_else(|| FrostWalletError::InvalidState(
                    format!("UTXO not found: {}:{}", input.previous_output.txid, input.previous_output.vout)))?;

            prevouts.push(TxOut {
                value: Amount::from_sat(utxo.amount),
                script_pubkey: ScriptBuf::from_bytes(utxo.script_pubkey.clone()),
            });
        }
        let prevouts = Prevouts::All(&prevouts);

        // For each input, we need to sign it
        let mut signed_tx = tx.clone();

        for (input_index, input) in tx.input.iter().enumerate() {
            // Find the UTXO being spent
            let utxo = self.utxos.iter()
                .find(|u| {
                    let txid = Txid::from_str(&u.txid).expect("Invalid txid format");
                    txid == input.previous_output.txid && u.vout == input.previous_output.vout
                })
                .ok_or_else(|| FrostWalletError::InvalidState(
                    format!("UTXO not found: {}:{}", input.previous_output.txid, input.previous_output.vout)))?;

            // Create script from script_pubkey
            let script = ScriptBuf::from_bytes(utxo.script_pubkey.clone());

            // Add witness UTXO to PSBT
            psbt.inputs[input_index].witness_utxo = Some(TxOut {
                value: Amount::from_sat(utxo.amount),
                script_pubkey: script.clone(),
            });

            // Create a SighashCache for the transaction
            let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

            // For Taproot inputs, we need to create a TapSighash
            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::Default)
                .map_err(|e| FrostWalletError::BitcoinError(format!("Failed to compute Taproot sighash: {}", e)))?;

            // Convert the sighash to bytes for signing
            let sighash_bytes = sighash.as_byte_array().to_vec();

            // Sign the message with FROST
            let frost_signature = controller.sign_message(sighash_bytes.to_vec(), signers.clone()).await?;

            // Convert FROST signature to Bitcoin signature format
            let signature_bytes = frost_signature.serialize().unwrap();

            // Create a Schnorr signature for the input
            let secp = Secp256k1::verification_only();
            let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature_bytes)
                .map_err(|e| FrostWalletError::BitcoinError(format!("Invalid Schnorr signature: {}", e)))?;

            // Add the signature to the witness
            let mut witness = Witness::new();
            witness.push(schnorr_sig.as_ref().to_vec());
            signed_tx.input[input_index].witness = witness;
        }

        // Update transaction in history (as signed)
        let tx_hex = encode::serialize_hex(&signed_tx);

        if let Some(tx_entry) = self.transactions.iter_mut()
            .find(|t| t.txid == signed_tx.txid().to_string()) {
            tx_entry.raw_tx = tx_hex;
        } else {
            // Add as new transaction if not found
            let wallet_tx = WalletTransaction {
                txid: signed_tx.txid().to_string(),
                raw_tx: tx_hex,
                amount: 0, // Will be updated after broadcast
                fee: 0,    // Will be updated after broadcast
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                confirmed: false,
                block_height: None,
            };
            self.add_transaction(wallet_tx)?;
        }

        // Save wallet state
        self.save_state()?;
        Ok(signed_tx)
    }

    /// Broadcast a transaction to the Bitcoin network
    pub async fn broadcast_transaction(&mut self, tx: &Transaction) -> Result<String> {
        // Ensure we have an RPC client
        let rpc_client = self.rpc_client.as_ref()
            .ok_or_else(|| FrostWalletError::ConnectionError("Not connected to Bitcoin node".to_string()))?;

        // Serialize the transaction
        let tx_hex = encode::serialize_hex(tx);

        // Send to Bitcoin node
        log::info!("Broadcasting transaction: {}", tx.txid());
        let txid = rpc_client.send_raw_transaction(&tx_hex).await?;

        // Update transaction in history as broadcasted
        if let Some(tx_entry) = self.transactions.iter_mut()
            .find(|t| t.txid == txid.to_string()) {
            tx_entry.raw_tx = tx_hex;
        } else {
            // Should not happen, but add as new transaction if not found
            let wallet_tx = WalletTransaction {
                txid: txid.to_string(),
                raw_tx: tx_hex,
                amount: 0, // Will be updated after confirmation
                fee: 0,    // Will be updated after confirmation
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                confirmed: false,
                block_height: None,
            };
            self.add_transaction(wallet_tx)?;
        }

        // Remove spent UTXOs
        for input in &tx.input {
            let txid_str = input.previous_output.txid.to_string();
            self.remove_utxo(&txid_str, input.previous_output.vout)?;
        }

        // Save wallet state
        self.save_state()?;

        Ok(txid.to_string())
    }

    /// Get wallet balance
    pub async fn get_balance(&mut self) -> Result<WalletBalance> {
        // If connected to a node, sync UTXOs first
        if self.rpc_client.is_some() {
            self.sync_utxos().await?;
        }

        let confirmed: u64 = self.utxos.iter()
            .filter(|utxo| utxo.confirmed)
            .map(|utxo| utxo.amount)
            .sum();

        let unconfirmed: u64 = self.utxos.iter()
            .filter(|utxo| !utxo.confirmed)
            .map(|utxo| utxo.amount)
            .sum();

        Ok(WalletBalance {
            confirmed,
            unconfirmed,
            total: confirmed + unconfirmed,
        })
    }

    /// Add a UTXO to the wallet
    pub fn add_utxo(&mut self, utxo: WalletUtxo) -> Result<()> {
        // Check if UTXO already exists
        if self.utxos.iter().any(|u| u.txid == utxo.txid && u.vout == utxo.vout) {
            return Err(FrostWalletError::InvalidState(
                format!("UTXO already exists: {}:{}", utxo.txid, utxo.vout)));
        }

        self.utxos.push(utxo);
        self.save_state()?;

        Ok(())
    }

    /// Remove a UTXO from the wallet
    pub fn remove_utxo(&mut self, txid: &str, vout: u32) -> Result<()> {
        let initial_len = self.utxos.len();
        self.utxos.retain(|u| !(u.txid == txid && u.vout == vout));

        if self.utxos.len() == initial_len {
            return Err(FrostWalletError::InvalidState(
                format!("UTXO not found: {}:{}", txid, vout)));
        }

        self.save_state()?;

        Ok(())
    }

    /// Add a transaction to the wallet history
    pub fn add_transaction(&mut self, tx: WalletTransaction) -> Result<()> {
        // Check if transaction already exists
        if self.transactions.iter().any(|t| t.txid == tx.txid) {
            return Err(FrostWalletError::InvalidState(
                format!("Transaction already exists: {}", tx.txid)));
        }

        self.transactions.push(tx);
        self.save_state()?;

        Ok(())
    }

    /// Save wallet state to disk
    pub fn save_state(&self) -> Result<()> {
        let wallet_state = WalletState {
            config: self.config.clone(),
            key_package: self.key_package.clone(),
            pub_key_package: self.pub_key_package.clone(),
            utxos: self.utxos.clone(),
            transactions: self.transactions.clone(),
        };

        let state_path = self.storage_path.join("wallet.json");
        let state_json = serde_json::to_string_pretty(&wallet_state)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize wallet state: {}", e)))?;

        fs::write(&state_path, state_json)
            .map_err(|e| FrostWalletError::IoError(e))?;

        Ok(())
    }

    /// Load wallet state from disk
    pub fn load_state(&mut self) -> Result<()> {
        let state_path = self.storage_path.join("wallet.json");

        if !state_path.exists() {
            return Err(FrostWalletError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Wallet state file not found: {:?}", state_path)
            )));
        }

        let state_json = fs::read_to_string(&state_path)
            .map_err(|e| FrostWalletError::IoError(e))?;

        let wallet_state: WalletState = serde_json::from_str(&state_json)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize wallet state: {}", e)))?;

        self.config = wallet_state.config;
        self.key_package = wallet_state.key_package;
        self.pub_key_package = wallet_state.pub_key_package;
        self.utxos = wallet_state.utxos;
        self.transactions = wallet_state.transactions;

        Ok(())
    }
}

/// Wallet state for serialization/deserialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletState {
    config: WalletConfig,
    key_package: Option<KeyPackage>,
    pub_key_package: Option<PublicKeyPackage>,
    utxos: Vec<WalletUtxo>,
    transactions: Vec<WalletTransaction>,
}

/// Utility functions for working with Bitcoin and FROST
pub mod utils {
    use super::*;
    use bitcoin::{Transaction, consensus::encode, ScriptBuf};

    /// Deserialize a hex string to a Bitcoin transaction
    pub fn deserialize_tx(tx_hex: &str) -> Result<Transaction> {
        let tx_bytes = hex::decode(tx_hex)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to decode transaction hex: {}", e)))?;

        let tx: Transaction = encode::deserialize(&tx_bytes)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize transaction: {}", e)))?;

        Ok(tx)
    }

    /// Serialize a Bitcoin transaction to a hex string
    pub fn serialize_tx(tx: &Transaction) -> Result<String> {
        let tx_bytes = encode::serialize(tx);
        let tx_hex = hex::encode(tx_bytes);

        Ok(tx_hex)
    }

    /// Convert a FROST signature to a Bitcoin signature
    pub fn frost_sig_to_bitcoin_sig(signature: &Signature) -> Vec<u8> {
        signature.serialize().unwrap()
    }

    /// Create a PSBT for signing with FROST
    pub fn create_psbt_for_frost(tx: &Transaction, input_utxos: &[WalletUtxo]) -> Result<Psbt> {
        let mut psbt = Psbt::from_unsigned_tx(tx.clone())
            .map_err(|e| FrostWalletError::InvalidState(format!("Failed to create PSBT: {}", e)))?;

        // Add UTXO information to inputs
        for (input_index, input) in tx.input.iter().enumerate() {
            // Find the corresponding UTXO
            let utxo = input_utxos.iter()
                .find(|u| {
                    let txid = Txid::from_str(&u.txid).expect("Invalid txid format");
                    txid == input.previous_output.txid && u.vout == input.previous_output.vout
                })
                .ok_or_else(|| FrostWalletError::InvalidState(
                    format!("UTXO not found: {}:{}", input.previous_output.txid, input.previous_output.vout)))?;

            // Create the script from the raw bytes
            let script = ScriptBuf::from_bytes(utxo.script_pubkey.clone());

            psbt.inputs[input_index].witness_utxo = Some(bitcoin::TxOut {
                value: Amount::from_sat(utxo.amount),
                script_pubkey: script,
            });
        }

        Ok(psbt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::rpc::MockBitcoinRpcClient;
    use crate::frost_dkg::chilldkg::{DkgCoordinator, DkgRoundState};
    use crate::common::types::Participant;
    use frost_core::Identifier;
    use frost_secp256k1::keys::dkg::{round1, round2};
    use std::sync::Arc;
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use rand::rngs::OsRng;

    /// Test wallet key generation with real FROST DKG
    #[tokio::test]
    async fn test_wallet_with_real_dkg() -> Result<()> {
        // Create a temporary directory for wallet data
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path();

        // Create wallet configuration (2-of-3 threshold scheme)
        let threshold = 2;
        let total_participants = 3;
        let config = WalletConfig::new(threshold, total_participants, Network::Regtest);

        // Create participant IDs
        let participant_ids = vec![
            Identifier::try_from(1u16).unwrap(),
            Identifier::try_from(2u16).unwrap(),
            Identifier::try_from(3u16).unwrap(),
        ];

        // Create wallets for each participant
        let mut wallets = Vec::new();
        for &id in &participant_ids {
            let mut wallet = BitcoinFrostWallet::new(id, config.clone(), storage_path);
            wallet.initialize().await?;
            wallets.push(wallet);
        }

        // Create DKG coordinators for each participant
        let mut coordinators = Vec::new();
        for &id in &participant_ids {
            let coordinator = DkgCoordinator::new(ThresholdConfig::new(threshold, total_participants));
            coordinators.push((id, coordinator));
        }

        // Register all participants with each coordinator
        for &id in &participant_ids {
            for (_, coordinator) in &mut coordinators {
                coordinator.add_participant(Participant::new(id))?;
            }
        }

        // Start DKG process for all participants
        for (_, coordinator) in &mut coordinators {
            coordinator.start()?;
        }

        // Round 1: Generate and share commitments
        // Each participant generates a round1 package and shares it with all other participants
        let mut round1_packages = BTreeMap::new();

        for (id, coordinator) in &mut coordinators {
            // Generate round1 package for this participant
            let round1_package = coordinator.generate_round1(*id)?;
            round1_packages.insert(*id, round1_package);
        }

        println!("I am here - nerd");

        // Process all round1 packages by all participants
        for (_, coordinator) in &mut coordinators {
            for (id, package) in &round1_packages {
                coordinator.process_round1_package(*id, package.clone())?;
            }
        }

        // Verify all coordinators are in Round2 state
        for (id, coordinator) in &coordinators {
            assert_eq!(*coordinator.get_round_state(), DkgRoundState::Round2,
                       "Coordinator for participant {:?} should be in Round2 state", id);
        }

        // Round 2: Generate and share key packages
        let mut round2_packages_map = BTreeMap::new();

        for (id, coordinator) in &mut coordinators {
            // Generate round2 packages for this participant
            let round2_packages = coordinator.generate_round2(*id)?;
            round2_packages_map.insert(*id, round2_packages);
        }

        // Process all round2 packages by their recipients
        for (sender_id, packages) in &round2_packages_map {
            for (recipient_id, package) in packages {
                for (id, coordinator) in &mut coordinators {
                    if id == recipient_id {
                        // Collect all packages for this recipient
                        let mut recipient_packages = BTreeMap::new();
                        recipient_packages.insert(*sender_id, package.clone());

                        // Process the round2 package
                        coordinator.process_round2_package(*sender_id, recipient_packages)?;
                    }
                }
            }
        }

        // Verify all coordinators are in Round3 state
        for (id, coordinator) in &coordinators {
            assert_eq!(*coordinator.get_round_state(), DkgRoundState::Round3,
                       "Coordinator for participant {:?} should be in Round3 state", id);
        }

        // Round 3: Finalize DKG and generate key packages
        let mut key_packages = BTreeMap::new();
        let mut public_key_packages = Vec::new();

        for (id, coordinator) in &mut coordinators {
            // Finalize DKG for this participant
            let key_package = coordinator.finalize(*id)?;
            key_packages.insert(*id, key_package.clone());

            // Get the public key package
            let pub_key_package = coordinator.get_public_key_package()?;
            public_key_packages.push(pub_key_package);

            // Verify coordinator is in Complete state
            assert_eq!(*coordinator.get_round_state(), DkgRoundState::Complete,
                       "Coordinator for participant {:?} should be in Complete state", id);
        }

        // Verify all participants have the same group public key
        let reference_pubkey = public_key_packages[0].verifying_key();
        for (idx, pub_key_package) in public_key_packages.iter().enumerate().skip(1) {
            assert_eq!(reference_pubkey, pub_key_package.verifying_key(),
                       "Public key package for participant {} differs from reference", idx + 1);
        }

        // Setup each wallet with its key package
        for (i, &id) in participant_ids.iter().enumerate() {
            wallets[i].key_package = Some(key_packages[&id].clone());
            wallets[i].pub_key_package = Some(public_key_packages[0].clone());

            // Verify the wallet's key package
            assert!(wallets[i].key_package.is_some(), "Wallet {} should have a key package", i + 1);

            // Save wallet state
            wallets[i].save_state()?;
        }

        // Verify all wallets generate the same address
        let addresses = wallets.iter()
            .map(|wallet| wallet.get_address().unwrap())
            .collect::<Vec<_>>();

        for i in 1..addresses.len() {
            assert_eq!(addresses[0].to_string(), addresses[i].to_string(),
                       "Wallet {} generated different address than wallet 1", i + 1);
        }

        println!("DKG successful! All wallets sharing the group address: {}", addresses[0]);

        // Create mock Bitcoin RPC client for transaction testing
        let mut rpc_client = MockBitcoinRpcClient::new(Network::Regtest);

        // Add UTXO to the group address
        let script_pubkey = addresses[0].script_pubkey();
        let utxo = crate::rpc::rpc::Utxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            vout: 0,
            address: addresses[0].to_string(),
            script_pub_key: hex::encode(script_pubkey.as_bytes()),
            amount: Amount::from_sat(100_000),
            confirmations: 6,
            spendable: true,
            solvable: true,
            safe: true,
        };

        rpc_client.add_utxo(utxo);

        // Connect the first wallet to the RPC client
        wallets[0].connect_to_node(Arc::new(rpc_client));

        // Sync UTXOs
        wallets[0].sync_utxos().await?;

        // Verify wallet received the UTXO
        assert_eq!(wallets[0].utxos.len(), 1, "Wallet should have 1 UTXO after syncing");
        assert_eq!(wallets[0].utxos[0].amount, 100_000, "UTXO amount should be 100,000 satoshis");

        // Create a transaction
        let recipient = "bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cpt8";
        let amount = 50_000;
        let fee_rate = 1.0;

        let tx = wallets[0].create_transaction(recipient, amount, fee_rate).await?;

        // Verify transaction outputs
        assert_eq!(tx.output.len(), 2, "Transaction should have 2 outputs (payment and change)");
        assert_eq!(tx.output[0].value.to_sat(), amount, "Payment amount should match");

        // Let's create signatures using the FROST DKG results
        let signers = vec![participant_ids[0], participant_ids[1]]; // 2-of-3 signing

        // Sign the transaction
        let signed_tx = wallets[0].sign_transaction(&tx, signers).await?;

        // Verify transaction is properly signed
        assert!(!signed_tx.input[0].witness.is_empty(), "Transaction should have a witness for the signature");

        // Verify wallet state contains the transaction
        assert_eq!(wallets[0].transactions.len(), 1, "Wallet should have 1 transaction in its history");

        Ok(())
    }

    /// Test FROST threshold signing with 3 participants using DKG-generated keys
    #[tokio::test]
    #[ignore]
    async fn test_threshold_signing_with_dkg_keys() -> Result<()> {
        // Create a temporary directory for wallet data
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path();

        // Initialize configurations
        let threshold = 2;
        let total_participants = 3;
        let config = WalletConfig::new(threshold, total_participants, Network::Regtest);

        // Create participant IDs
        let participant_ids = vec![
            Identifier::try_from(1u16).unwrap(),
            Identifier::try_from(2u16).unwrap(),
            Identifier::try_from(3u16).unwrap(),
        ];

        // Perform DKG to get key packages

        // Create DKG coordinators for each participant
        let mut coordinators = Vec::new();
        for &id in &participant_ids {
            let coordinator = DkgCoordinator::new(ThresholdConfig::new(threshold, total_participants));
            coordinators.push((id, coordinator));
        }

        // Register all participants with each coordinator
        for &id in &participant_ids {
            for (_, coordinator) in &mut coordinators {
                coordinator.add_participant(Participant::new(id))?;
            }
        }

        // Start DKG process
        for (_, coordinator) in &mut coordinators {
            coordinator.start()?;
        }

        // Run DKG Round 1
        let mut round1_packages = BTreeMap::new();
        for (id, coordinator) in &mut coordinators {
            let package = coordinator.generate_round1(*id)?;
            round1_packages.insert(*id, package);
        }

        for (_, coordinator) in &mut coordinators {
            for (id, package) in &round1_packages {
                coordinator.process_round1_package(*id, package.clone())?;
            }
        }

        // Run DKG Round 2
        let mut round2_packages_map = BTreeMap::new();
        for (id, coordinator) in &mut coordinators {
            let packages = coordinator.generate_round2(*id)?;
            round2_packages_map.insert(*id, packages);
        }

        for (_, coordinator) in &mut coordinators {
            for (sender_id, packages) in &round2_packages_map {
                for (recipient_id, package) in packages {
                    if coordinator.get_participant(*recipient_id).is_some() {
                        let mut recipient_packages = BTreeMap::new();
                        recipient_packages.insert(*sender_id, package.clone());
                        coordinator.process_round2_package(*sender_id, recipient_packages)?;
                    }
                }
            }
        }

        // Finalize DKG
        let mut key_packages = BTreeMap::new();
        let mut public_key_packages = Vec::new();

        for (id, coordinator) in &mut coordinators {
            let key_package = coordinator.finalize(*id)?;
            key_packages.insert(*id, key_package);
            public_key_packages.push(coordinator.get_public_key_package()?);
        }

        // Create signing controllers for each participant
        let mut signing_controllers = Vec::new();
        for (i, &id) in participant_ids.iter().enumerate() {
            let mut controller = SigningProcessController::new(
                id,
                ThresholdConfig::new(threshold, total_participants),
            );

            controller.set_key_package(
                key_packages[&id].clone(),
                public_key_packages[0].clone()
            )?;

            signing_controllers.push(controller);
        }

        // Create a message to sign
        let message = b"Test message for FROST signing".to_vec();

        // Select signers (2-of-3)
        let signing_participant_ids = vec![participant_ids[0], participant_ids[1]];

        // Sign the message with the first signing controller
        let signature = signing_controllers[0].sign_message(message.clone(), signing_participant_ids.clone()).await?;

        // Verify the signature
        let verifying_key = public_key_packages[0].verifying_key();
        let valid = frost_secp256k1::VerifyingKey::verify(
            verifying_key,
            &message,
            &signature
        ).is_ok();

        assert!(valid, "Signature verification failed");

        // Create wallets and set them up with the key packages
        let mut wallets = Vec::new();
        for (i, &id) in participant_ids.iter().enumerate() {
            let mut wallet = BitcoinFrostWallet::new(id, config.clone(), storage_path);
            wallet.initialize().await?;
            wallet.key_package = Some(key_packages[&id].clone());
            wallet.pub_key_package = Some(public_key_packages[i].clone());

            // Create the controller directly here instead of in a separate collection
            let mut controller = SigningProcessController::new(
                id,
                ThresholdConfig::new(threshold, total_participants),
            );

            controller.set_key_package(
                key_packages[&id].clone(),
                public_key_packages[i].clone()
            )?;

            wallet.signing_controller = Some(controller);
            wallets.push(wallet);
        }

        // Get wallet address
        let wallet_address = wallets[0].get_address()?;

        // Add UTXO to the first wallet
        let utxo = WalletUtxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            vout: 0,
            amount: 100_000,
            script_pubkey: wallet_address.script_pubkey().as_bytes().to_vec(),
            confirmed: true,
            block_height: Some(100),
        };

        wallets[0].add_utxo(utxo)?;

        // Create a transaction
        let recipient = "bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cpt8";
        let amount = 50_000;
        let fee_rate = 1.0;

        let tx = wallets[0].create_transaction(recipient, amount, fee_rate).await?;

        // Sign the transaction using the FROST threshold signature
        let signed_tx = wallets[0].sign_transaction(&tx, signing_participant_ids).await?;

        // Verify transaction is properly signed
        assert!(!signed_tx.input[0].witness.is_empty(), "Transaction should have a witness for the signature");

        // Create a mock RPC client to broadcast the transaction
        let mut mock_client = MockBitcoinRpcClient::new(Network::Regtest);
        wallets[0].connect_to_node(Arc::new(mock_client));

        // Broadcast the transaction
        let txid = wallets[0].broadcast_transaction(&signed_tx).await?;

        assert_eq!(txid, signed_tx.txid().to_string(), "Transaction ID should match");

        // Verify the UTXO was removed from the wallet
        assert_eq!(wallets[0].utxos.len(), 0, "UTXO should be removed after spending");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_multi_wallet_transaction_lifecycle() -> Result<()> {
        // Create temporary directory for wallet data
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path();

        // Initialize configurations
        let threshold = 2;
        let total_participants = 3;
        let config = WalletConfig::new(threshold, total_participants, Network::Regtest);

        // Create participant IDs
        let participant_ids = vec![
            Identifier::try_from(1u16).unwrap(),
            Identifier::try_from(2u16).unwrap(),
            Identifier::try_from(3u16).unwrap(),
        ];

        // Create DKG coordinators for each participant
        let mut coordinators = Vec::new();
        for &id in &participant_ids {
            let coordinator = DkgCoordinator::new(ThresholdConfig::new(threshold, total_participants));
            coordinators.push((id, coordinator));
        }

        // Register all participants with each coordinator
        for &id in &participant_ids {
            for (_, coordinator) in &mut coordinators {
                coordinator.add_participant(Participant::new(id))?;
            }
        }

        // Start DKG process
        for (_, coordinator) in &mut coordinators {
            coordinator.start()?;
        }

        // Run DKG Round 1
        let mut round1_packages = BTreeMap::new();
        for (id, coordinator) in &mut coordinators {
            let package = coordinator.generate_round1(*id)?;
            round1_packages.insert(*id, package);
        }

        for (id, package) in &round1_packages {
            for (_, coordinator) in &mut coordinators {
                coordinator.process_round1_package(*id, package.clone())?;
            }
        }

        // Run DKG Round 2
        let mut round2_packages_map = BTreeMap::new();
        for (id, coordinator) in &mut coordinators {
            let packages = coordinator.generate_round2(*id)?;
            round2_packages_map.insert(*id, packages);
        }

        for (sender_id, packages) in &round2_packages_map {
            for (recipient_id, package) in packages {
                for (id, coordinator) in &mut coordinators {
                    if id == recipient_id {
                        let mut recipient_packages = BTreeMap::new();
                        recipient_packages.insert(*sender_id, package.clone());
                        coordinator.process_round2_package(*sender_id, recipient_packages)?;
                    }
                }
            }
        }

        // Finalize DKG and get key packages
        let mut key_packages = BTreeMap::new();
        let mut pub_key_package = None;

        for (id, coordinator) in &mut coordinators {
            let key_package = coordinator.finalize(*id)?;
            key_packages.insert(*id, key_package);
            pub_key_package = Some(coordinator.get_public_key_package()?);
        }

        let pub_key_package = pub_key_package.unwrap();

        // Create wallets for each participant
        let mut wallets = Vec::new();
        for &id in &participant_ids {
            let mut wallet = BitcoinFrostWallet::new(id, config.clone(), storage_path);
            wallet.initialize().await?;
            wallet.key_package = Some(key_packages[&id].clone());
            wallet.pub_key_package = Some(pub_key_package.clone());

            // Initialize signing controller
            let mut controller = SigningProcessController::new(
                id,
                ThresholdConfig::new(threshold, total_participants),
            );

            controller.set_key_package(
                key_packages[&id].clone(),
                pub_key_package.clone()
            )?;

            wallet.signing_controller = Some(controller);

            wallets.push(wallet);
        }

        // Verify all wallets have the same address
        let wallet_address = wallets[0].get_address()?;
        for (i, wallet) in wallets.iter().enumerate().skip(1) {
            assert_eq!(wallet_address.to_string(), wallet.get_address()?.to_string(),
                       "Wallet {} has different address", i + 1);
        }

        // Create a mock RPC client
        let mut mock_client = MockBitcoinRpcClient::new(Network::Regtest);

        // Add UTXO to the shared wallet address
        let utxo = crate::rpc::rpc::Utxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            vout: 0,
            address: wallet_address.to_string(),
            script_pub_key: hex::encode(wallet_address.script_pubkey().as_bytes()),
            amount: Amount::from_sat(100_000),
            confirmations: 6,
            spendable: true,
            solvable: true,
            safe: true,
        };

        mock_client.add_utxo(utxo);

        // Connect the wallets to the RPC client
        for wallet in &mut wallets {
            wallet.connect_to_node(Arc::new(mock_client.clone()));
            wallet.sync_utxos().await?;
        }

        // Verify all wallets received the UTXO
        for (i, wallet) in wallets.iter().enumerate() {
            assert_eq!(wallet.utxos.len(), 1, "Wallet {} should have 1 UTXO", i + 1);
        }

        // Create a transaction with the first wallet
        let recipient = "bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cpt8";
        let amount = 50_000;
        let fee_rate = 1.0;

        let tx = wallets[0].create_transaction(recipient, amount, fee_rate).await?;

        // Select signers for threshold signing (2-of-3)
        let signers = vec![participant_ids[0], participant_ids[1]];

        // Sign with the first wallet
        let signed_tx = wallets[0].sign_transaction(&tx, signers).await?;

        // Verify transaction is properly signed
        assert!(!signed_tx.input[0].witness.is_empty(), "Transaction should have a witness signature");

        // Broadcast the transaction
        let txid = wallets[0].broadcast_transaction(&signed_tx).await?;

        // Verify the transaction was broadcast successfully
        assert_eq!(txid, signed_tx.txid().to_string(), "Transaction ID should match");

        // Sync all wallets to reflect the spent UTXO
        for wallet in &mut wallets {
            wallet.sync_utxos().await?;
        }

        // Verify all wallets have no UTXOs after spending
        for (i, wallet) in wallets.iter().enumerate() {
            assert_eq!(wallet.utxos.len(), 0, "Wallet {} should have 0 UTXOs after spending", i + 1);
        }

        // Verify all wallets have the transaction in their history
        for (i, wallet) in wallets.iter().enumerate() {
            assert_eq!(wallet.transactions.len(), 1, "Wallet {} should have 1 transaction in history", i + 1);
        }

        Ok(())
    }
}