use crate::common::errors::{FrostWalletError, Result};
use crate::wallet::storage::WalletStorage;
use bitcoin::{Address, Network, Script, ScriptBuf};
use frost_secp256k1::VerifyingKey;
use bitcoin::{secp256k1::{Secp256k1, XOnlyPublicKey, Message, VerifyOnly}};
use std::str::FromStr;

pub struct AddressManager {
    /// Bitcoin network (mainnet, testnet, etc.)
    network: Network,
    /// Reference to wallet storage
    storage: WalletStorage,
    /// Secp256k1 context for address generation
    secp: Secp256k1<VerifyOnly>,
}

impl AddressManager {
    /// Create a new address manager
    pub fn new(network: Network, storage: &WalletStorage) -> Result<Self> {
        Ok(Self {
            network,
            storage: storage.clone(),
            secp: Secp256k1::verification_only(),
        })
    }

    /// Generate a new P2TR (Pay-to-Taproot) address from the FROST public key
    pub fn new_address(&mut self) -> Result<Address> {
        // Get FROST public key from storage
        let public_key = self.storage.get_frost_public_key()?;

        // Convert to Secp256k1 X-only public key for Taproot
        let pk_bytes = public_key.serialize().unwrap();
        let xonly_pk = XOnlyPublicKey::from_slice(&pk_bytes[..])
            .map_err(|e| FrostWalletError::Secp256k1Error(e))?;

        // Create Taproot output script
        let tr_script = ScriptBuf::new_p2tr(&self.secp, xonly_pk, None);

        // Create Bitcoin address
        let address = Address::from_script(&tr_script, self.network)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to create address: {:?}", e)))?;

        // Save address to storage
        self.storage.save_address(&address)?;

        Ok(address)
    }

    /// Get all addresses associated with the wallet
    pub fn get_addresses(&self) -> Result<Vec<Address>> {
        self.storage.get_addresses()
    }

    /// Check if an address belongs to this wallet
    pub fn is_owned_address(&self, address: &Address) -> Result<bool> {
        let addresses = self.get_addresses()?;
        Ok(addresses.contains(address))
    }

    /// Get latest address
    pub fn get_latest_address(&self) -> Result<Address> {
        let addresses = self.get_addresses()?;

        if addresses.is_empty() {
            return Err(FrostWalletError::InvalidState("No addresses found".to_string()));
        }

        // Return the most recently created address
        Ok(addresses.last().unwrap().clone())
    }

    /// Generate an internal change address
    /// In a real implementation, this would use a different derivation path
    pub fn get_change_address(&self) -> Result<Address> {
        // For simplicity, we're using the latest address as the change address
        // In a production wallet, you'd generate a new address on an internal chain
        self.get_latest_address()
    }
}