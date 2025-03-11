use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{WalletConfig, ThresholdConfig};
use crate::frost_dkg::chilldkg::DkgCoordinator;
use crate::frost_dkg::dkg_process::DkgProcessController;
use crate::frost_dkg::frost::FrostCoordinator;
use crate::frost_dkg::signing_process::SigningProcessController;

use bitcoin::{
    Address, Network, ScriptBuf, Transaction, TxIn, TxOut, OutPoint,
    consensus::encode::serialize_hex, sighash::TapSighash, Amount, hashes::Hash,
    psbt::Psbt, secp256k1::{Secp256k1, XOnlyPublicKey, Message},
    Txid, transaction, Sequence, Witness
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
use tokio::sync::Mutex;

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
        }
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

    /// Create a Bitcoin transaction
    pub fn create_transaction(
        &self,
        recipient: &str,
        amount: u64,
        fee_rate: f64
    ) -> Result<Transaction> {
        // Check if wallet is initialized
        if self.key_package.is_none() || self.pub_key_package.is_none() {
            return Err(FrostWalletError::InvalidState("Wallet not initialized".to_string()));
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
            return Err(FrostWalletError::InvalidState(
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
                // Fix: Use Txid::from_str instead of from_hex
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
                value: Amount::from_sat(change_amount),  // Fix: Use Amount::from_sat
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

        Ok(tx)
    }

    /// Sign a transaction
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

        // For each input, we need to sign it
        for (input_index, input) in tx.input.iter().enumerate() {
            // Find the UTXO being spent
            let utxo = self.utxos.iter()
                .find(|u| {
                    let txid = Txid::from_str(&u.txid).expect("Invalid txid format");
                    txid == input.previous_output.txid && u.vout == input.previous_output.vout
                })
                .ok_or_else(|| FrostWalletError::InvalidState(
                    format!("UTXO not found: {}:{}", input.previous_output.txid, input.previous_output.vout)))?;

            // In a real implementation, we would properly handle the sighash creation
            // For simplicity, let's just use a hash of the transaction as the message to sign
            let tx_bytes = encode::serialize(tx);
            let message = tx_bytes.to_vec();

            // Sign the message with FROST
            let frost_signature = controller.sign_message(message, signers.clone()).await?;

            // Convert FROST signature to Bitcoin signature format
            // Note: This is a simplified version - in a real implementation we would need
            // proper signature format conversion
            let signature_bytes = frost_signature.serialize().unwrap();

            // For a proper implementation, we would need to handle the signature insertion
            // into the PSBT correctly based on the input type (p2pkh, p2sh, p2wpkh, p2tr, etc.)
            // This is a simplified example that won't actually work with real Bitcoin transactions
            // because we're not handling the signature and sighash properly
        }

        // In a real implementation, we would finalize the PSBT properly
        // For now, just return the original transaction as a placeholder
        Ok(tx.clone())
    }

    /// Broadcast a transaction to the Bitcoin network
    /// Note: this is a placeholder and would need to connect to a Bitcoin node
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<String> {
        // In a real implementation, you would connect to a Bitcoin node
        // and broadcast the transaction using its RPC interface.
        // For now, we'll just return the transaction ID.

        let txid = tx.txid().to_string();
        log::info!("Broadcasting transaction: {}", txid);

        // In a real implementation:
        // 1. Serialize the transaction
        let tx_bytes = encode::serialize(tx);
        let tx_hex = hex::encode(tx_bytes);

        // 2. Send to Bitcoin node
        // bitcoind_client.sendrawtransaction(tx_hex)

        // 3. Return the transaction ID
        Ok(txid)
    }

    /// Get wallet balance
    pub fn get_balance(&self) -> WalletBalance {
        let confirmed: u64 = self.utxos.iter()
            .filter(|utxo| utxo.confirmed)
            .map(|utxo| utxo.amount)
            .sum();

        let unconfirmed: u64 = self.utxos.iter()
            .filter(|utxo| !utxo.confirmed)
            .map(|utxo| utxo.amount)
            .sum();

        WalletBalance {
            confirmed,
            unconfirmed,
            total: confirmed + unconfirmed,
        }
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