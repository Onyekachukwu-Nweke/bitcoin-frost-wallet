use crate::frost::coordinator::CoordinatorController;
use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{SigningRequest, ThresholdConfig};
use crate::wallet::{AddressManager, TransactionManager, WalletStorage, NodeClient};
use bitcoin::{Network, Transaction};
use std::path::PathBuf;

pub struct BitcoinWallet {
    /// Network (mainnet, testnet, etc.)
    network: Network,
    /// Address manager
    address_manager: AddressManager,
    /// Transaction manager
    tx_manager: TransactionManager,
    /// Wallet storage
    storage: WalletStorage,
    /// Node client for communication with Bitcoin node
    node_client: NodeClient,
    /// Reference to FROST coordinator for signing
    frost_coordinator: Option<CoordinatorController>,
}

impl BitcoinWallet {
    /// Create a new Bitcoin wallet
    pub fn new(network: Network, storage_path: PathBuf, socket_path: Option<&str>) -> Result<Self> {
        let storage = WalletStorage::new(storage_path)?;
        let address_manager = AddressManager::new(network, &storage)?;
        let tx_manager = TransactionManager::new(network, &storage)?;
        let node_client = NodeClient::connect(socket_path)?;

        Ok(Self {
            network,
            address_manager,
            tx_manager,
            storage,
            node_client,
            frost_coordinator: None,
        })
    }

    /// Connect to FROST coordinator
    pub fn connect_frost_coordinator(&mut self, coordinator: CoordinatorController) {
        self.frost_coordinator = Some(coordinator);
    }

    /// Create a new address
    pub fn new_address(&mut self) -> Result<bitcoin::Address> {
        self.address_manager.new_address()
    }

    /// Create a transaction
    pub fn create_transaction(&self, recipient: bitcoin::Address, amount: u64, fee_rate: f32) -> Result<Transaction> {
        self.tx_manager.create_transaction(recipient, amount, fee_rate)
    }

    /// Sign a transaction using FROST
    pub async fn sign_transaction(&self, tx: Transaction, signers: Vec<frost_secp256k1::Identifier>) -> Result<Transaction> {
        let coordinator = self.frost_coordinator.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No FROST coordinator connected".to_string()))?;

        // Prepare signing request
        let signing_request = SigningRequest {
            transaction: tx.clone(),
            input_index: 0, // Handle multiple inputs as well
            input_value: 0, // Calculate from UTXO
            signers,
        };

        // Sign using the FROST coordinator
        let signed_tx = self.tx_manager.apply_signature(tx, signing_request, coordinator).await?;

        Ok(signed_tx)
    }

    /// Broadcast a transaction
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<bitcoin::Txid> {
        self.node_client.broadcast_transaction(tx).await
    }
}