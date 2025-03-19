use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{SigningRequest};
use crate::frost::coordinator::FrostCoordinator;
use crate::wallet::storage::WalletStorage;
use crate::wallet::address::AddressManager;
use bitcoin::{
    Address, Network, Transaction, TxIn, TxOut, Witness, Script, ScriptBuf,
    OutPoint, Txid, Amount, secp256k1::{Secp256k1, XOnlyPublicKey, Message, VerifyOnly, schnorr},
    Sequence, transaction, hashes::Hash, absolute::LockTime,
    sighash::{TapSighash, TapSighashType, SighashCache}
};

/// Representation of an Unspent Transaction Output
#[derive(Clone, Debug)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub amount: u64,
    pub address: Address,
    pub script_pubkey: ScriptBuf,
}

pub struct TransactionManager {
    /// Bitcoin network
    network: Network,
    /// Reference to wallet storage
    storage: WalletStorage,
    /// Secp256k1 context for signature verification
    secp: Secp256k1<VerifyOnly>,
}

impl TransactionManager {
    /// Create a new transaction manager
    pub fn new(network: Network, storage: &WalletStorage) -> Result<Self> {
        Ok(Self {
            network,
            storage: storage.clone(),
            secp: Secp256k1::verification_only(),
        })
    }

    /// Create a transaction
    pub fn create_transaction(&self, recipient: Address, amount: u64, fee_rate: f32) -> Result<Transaction> {
        // Get available UTXOs
        let utxos = self.storage.get_utxos()?;

        if utxos.is_empty() {
            return Err(FrostWalletError::InvalidState("No UTXOs available".to_string()));
        }

        // Simple coin selection - we'll sort by amount and use the smallest UTXOs first
        // In a real wallet, you'd implement a more sophisticated coin selection algorithm
        let mut selected_utxos: Vec<Utxo> = Vec::new();
        let mut total_input = 0;

        // Sort UTXOs by amount (smallest first)
        let mut sorted_utxos = utxos.clone();
        sorted_utxos.sort_by(|a, b| a.amount.cmp(&b.amount));

        // Select UTXOs until we have enough to cover amount + estimated fee
        // This is a very basic algorithm and doesn't account for change output fee
        let estimated_tx_size = 150 + (sorted_utxos.len() as u64 * 50); // Rough estimate
        let estimated_fee = (fee_rate * estimated_tx_size as f32) as u64;
        let target_amount = amount + estimated_fee;

        for utxo in sorted_utxos {
            selected_utxos.push(utxo.clone());
            total_input += utxo.amount;

            if total_input >= target_amount {
                break;
            }
        }

        if total_input < target_amount {
            return Err(FrostWalletError::InvalidState(format!(
                "Insufficient funds. Need {} satoshis, only have {}",
                target_amount, total_input
            )));
        }

        // Calculate change amount
        let change_amount = total_input - amount - estimated_fee;

        // Create transaction inputs
        let inputs: Vec<TxIn> = selected_utxos.iter().map(|utxo| {
            TxIn {
                previous_output: OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xFFFFFFFF), // RBF disabled
                witness: Witness::new(),
            }
        }).collect();

        // Create transaction outputs
        let mut outputs: Vec<TxOut> = Vec::new();

        // Add recipient output
        outputs.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: recipient.script_pubkey(),
        });

        // Add change output if needed
        if change_amount > 546 { // Dust threshold
            let address_manager = AddressManager::new(self.network, &self.storage)?;
            let change_address = address_manager.get_change_address()?;

            outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: change_address.script_pubkey(),
            });
        }

        // Create unsigned transaction
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // Store selected UTXOs with the unsigned transaction
        self.storage.save_unsigned_tx(&tx, &selected_utxos)?;

        Ok(tx)
    }

    /// Apply FROST signature to the transaction
    pub async fn apply_signature(
        &self,
        unsigned_tx: Transaction,
        signing_request: SigningRequest,
        frost_coordinator: &FrostCoordinator
    ) -> Result<Transaction> {
        // Get selected UTXOs for this transaction
        let utxos = self.storage.get_utxos_for_tx(&unsigned_tx)?;

        if utxos.is_empty() {
            return Err(FrostWalletError::InvalidState("No UTXOs found for transaction".to_string()));
        }

        // Get FROST public key
        let public_key = self.storage.get_frost_public_key()?;

        // Create mutable copy of transaction
        let mut tx = unsigned_tx.clone();

        // Sign each input
        for (i, utxo) in utxos.iter().enumerate() {
            // Prepare the signature hash for BIP 341 (Taproot)
            let sighash = self.create_taproot_sighash(&tx, i, &utxos)?;

            // Sign with FROST
            // Note: In a real implementation, you would need to adapt this to how your
            // FROST coordinator actually signs messages
            let signature = frost_coordinator.sign_message(&sighash, signing_request.signers.clone()).await?;

            // Create Schnorr signature witness
            let schnorr_sig = signature.to_bytes().to_vec();

            // Set the witness for this input
            tx.input[i].witness = Witness::from_slice(&[schnorr_sig]);
        }

        // Store the signed transaction
        self.storage.save_signed_tx(&tx)?;

        Ok(tx)
    }

    /// Create a Taproot signature hash according to BIP 341
    fn create_taproot_sighash(&self, tx: &Transaction, input_index: usize, utxos: &[Utxo]) -> Result<Vec<u8>> {
        // Verify input index is valid
        if input_index >= tx.input.len() {
            return Err(FrostWalletError::InvalidState(format!("Invalid input index: {}", input_index)));
        }

        // Find the corresponding UTXO
        let utxo = utxos.iter()
            .find(|u| {
                u.txid == tx.input[input_index].previous_output.txid &&
                    u.vout == tx.input[input_index].previous_output.vout
            })
            .ok_or_else(|| FrostWalletError::InvalidState(format!(
                "UTXO not found for input {} ({}:{})",
                input_index,
                tx.input[input_index].previous_output.txid,
                tx.input[input_index].previous_output.vout
            )))?;

        // Convert amount to bitcoin::Amount
        let amount = Amount::from_sat(utxo.amount);

        // Create sighash cache for the transaction
        let mut sighash_cache = SighashCache::new(tx);

        // Generate the signature hash for this input
        // Using SIGHASH_ALL for Taproot (default)
        let tap_sighash = sighash_cache.taproot_sign_hash(
            input_index,
            &bitcoin::ScriptBuf::new(), // No script path spending, so empty script
            bitcoin::ScriptBuf::new(),  // No annex
            TapSighashType::Default,    // SIGHASH_ALL in Taproot
            amount
        ).map_err(|e| FrostWalletError::SerializationError(format!("Sighash error: {:?}", e)))?;

        // Convert to bytes
        Ok(tap_sighash.as_ref().to_vec())
    }

    /// Estimate transaction fee
    pub fn estimate_fee(&self, tx: &Transaction, fee_rate: f32) -> u64 {
        // Rough size estimation
        let tx_size = bitcoin::consensus::serialize(tx).len() as f32;
        (tx_size * fee_rate) as u64
    }

    /// Verify a transaction signature
    pub fn verify_transaction(&self, tx: &Transaction) -> Result<bool> {
        // Get UTXOs for this transaction
        let utxos = self.storage.get_utxos_for_tx(tx)?;

        if utxos.is_empty() {
            return Err(FrostWalletError::InvalidState("No UTXOs found for transaction".to_string()));
        }

        // Get FROST public key
        let frost_pubkey = self.storage.get_frost_public_key()?;

        // Convert to XOnlyPublicKey
        let pk_bytes = frost_pubkey.serialize().unwrap();
        let xonly_pk = XOnlyPublicKey::from_slice(&pk_bytes[..])
            .map_err(|e| FrostWalletError::Secp256k1Error(e))?;

        // Verify each input
        for (i, utxo) in utxos.iter().enumerate() {
            // Get the signature from witness
            if tx.input[i].witness.len() < 1 {
                return Ok(false);
            }

            let sig_bytes = &tx.input[i].witness[0];

            // Create sighash
            let sighash = self.create_taproot_sighash(tx, i, &utxos)?;

            // Verify using secp256k1
            // This is a simplified version - in a real implementation you'd use the proper BIP 341 verification
            let message = Message::from_digest_slice(&sighash)
                .map_err(|e| FrostWalletError::SerializationError(format!("Invalid message: {:?}", e)))?;

            let signature = schnorr::Signature::from_slice(sig_bytes)
                .map_err(|e| FrostWalletError::SerializationError(format!("Invalid signature: {:?}", e)))?;

            if !self.secp.verify_schnorr(&signature, &message, &xonly_pk).is_ok() {
                return Ok(false);
            }
        }

        Ok(true)
    }
}