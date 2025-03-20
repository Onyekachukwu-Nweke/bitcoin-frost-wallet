use bdk_chain::{
    bitcoin::{self, Address, Network, Transaction, ScriptBuf, TxOut, taproot::TaprootBuilder},
    keychain_txout::KeychainTxOutIndex,
    local_chain::LocalChain,
    BlockId, CheckPoint, ConfirmationBlockTime, IndexedTxGraph, Merge,
};
use bdk_file_store::Store as BdkStore;
use frost_secp256k1::{Identifier, Signature, VerifyingKey, keys::{KeyPackage, PublicKeyPackage}};
use std::error::Error;
use bdk_chain::bitcoin::hashes::Hash;
use bdk_chain::bitcoin::sighash::{Prevouts, SighashCache};
use bdk_chain::bitcoin::TapSighashType;
use crate::common::types::ThresholdConfig;
use crate::frost::coordinator::CoordinatorController;

pub const NETWORK: Network = bitcoin::Network::Regtest;
pub const BDK_STORE_PATH: &str = "bdk_core_store.dat";
pub const BDK_STORE_MAGIC: &[u8] = b"bdk_core_store";
pub const SLEEP_BEFORE_DISCONNECT_SECS: u64 = 6;

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChangeSet {
    pub chain_cs: bdk_chain::local_chain::ChangeSet,
    pub graph_cs: bdk_chain::indexed_tx_graph::ChangeSet<
        ConfirmationBlockTime,
        bdk_chain::indexer::keychain_txout::ChangeSet,
    >,
    pub frost_pubkey_package: Option<PublicKeyPackage>,
}

impl Merge for ChangeSet {
    fn merge(&mut self, other: Self) {
        Merge::merge(&mut self.chain_cs, other.chain_cs);
        Merge::merge(&mut self.graph_cs, other.graph_cs);
        if self.frost_pubkey_package.is_none() {
            self.frost_pubkey_package = other.frost_pubkey_package;
        }
    }

    fn is_empty(&self) -> bool {
        self.chain_cs.is_empty() && self.graph_cs.is_empty() && self.frost_pubkey_package.is_none()
    }
}

pub struct BdkFrostWallet {
    pub chain: LocalChain,
    pub tx_graph: IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<()>>,
    pub store: BdkStore<ChangeSet>,
    pub coordinator: Option<CoordinatorController>,
    pub pub_key_package: PublicKeyPackage,
}

impl BdkFrostWallet {
    /// Create a new wallet with existing key material
    pub fn new(
        pub_key_package: PublicKeyPackage,
        store_path: Option<&str>,
    ) -> Result<Self, Box<dyn Error>> {
        let (mut chain, _) = LocalChain::from_genesis_hash(
            bitcoin::constants::genesis_block(NETWORK).block_hash()
        );
        let mut index = KeychainTxOutIndex::default();

        // Use provided store path or default
        let store_path = store_path.unwrap_or(BDK_STORE_PATH);
        let mut store = BdkStore::open_or_create_new(BDK_STORE_MAGIC, store_path)?;

        // Generate script from public key and add to index
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let xonly_pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &pub_key_package.verifying_key().serialize().unwrap()
        )?;

        // Create P2TR address directly without using TaprootBuilder
        let address = Address::p2tr(&secp, xonly_pk, None, NETWORK);
        let taproot_script = address.script_pubkey();

        index.index_of_spk(taproot_script);
        let mut tx_graph = IndexedTxGraph::new(index);

        // Set up initial state or load from existing store
        let mut wallet_pub_key_package = pub_key_package.clone();

        for cs in store.iter_changesets() {
            let cs: ChangeSet = cs?;
            chain.apply_changeset(&cs.chain_cs)?;
            tx_graph.apply_changeset(cs.graph_cs);
            if let Some(pp) = cs.frost_pubkey_package {
                wallet_pub_key_package = pp;
            }
        }

        // Create wallet instance
        let mut wallet = Self {
            chain,
            tx_graph,
            store,
            coordinator: None,
            pub_key_package: wallet_pub_key_package,
        };

        // Check and store initial data if needed before returning
        if wallet.store.iter_changesets().next().is_none() {
            wallet.store_frost_data()?;
        }

        Ok(wallet)
    }

    /// Connect to a FROST coordinator for signing operations
    pub fn connect_coordinator(
        &mut self,
        coordinator_id: Identifier,
        addr: std::net::SocketAddr,
        config: ThresholdConfig
    ) -> Result<(), Box<dyn Error>> {
        let mut coordinator = CoordinatorController::new(coordinator_id, config, addr.port());
        coordinator.set_public_key_package(self.pub_key_package.clone())?;
        self.coordinator = Some(coordinator);
        Ok(())
    }

    pub fn genesis_hash(&self) -> bitcoin::BlockHash {
        self.chain.genesis_hash()
    }

    pub fn tip(&self) -> BlockId {
        self.chain.tip().block_id()
    }

    pub fn apply_block(&mut self, block: &bitcoin::Block, height: i32) -> Result<(), Box<dyn Error>> {
        let h: u32 = height.try_into()?;
        let graph_cs = self.tx_graph.apply_block_relevant(block, h);
        let chain_cs = self.chain.apply_update(CheckPoint::from_header(&block.header, h))?;
        let cs = ChangeSet {
            graph_cs,
            chain_cs,
            frost_pubkey_package: Some(self.pub_key_package.clone()),
        };
        self.store.append_changeset(&cs)?;
        if !cs.graph_cs.is_empty() {
            println!("Graph change set not empty. New wallet state:");
            self.print_info()?;
        }
        Ok(())
    }

    pub fn apply_tx(&mut self, tx: Transaction) -> Result<(), Box<dyn Error>> {
        let graph_cs = self.tx_graph.batch_insert_relevant_unconfirmed([(tx, 0)]);
        let cs = ChangeSet {
            graph_cs,
            frost_pubkey_package: Some(self.pub_key_package.clone()),
            ..Default::default()
        };
        self.store.append_changeset(&cs)?;
        if !cs.graph_cs.is_empty() {
            println!("Graph change set not empty. New wallet state:");
            self.print_info()?;
        }
        Ok(())
    }

    pub fn disconnect(&mut self, block_id: BlockId) -> Result<(), Box<dyn Error>> {
        let chain_cs = if block_id.height > 0 {
            self.chain.disconnect_from(block_id)?
        } else {
            let mut cs = bdk_chain::local_chain::ChangeSet::default();
            for cp in self.chain.iter_checkpoints() {
                if cp.height() != 0 {
                    cs.blocks.insert(cp.height(), None);
                }
            }
            self.chain = LocalChain::from_genesis_hash(
                bitcoin::constants::genesis_block(NETWORK).block_hash()
            ).0;
            cs
        };
        let cs = ChangeSet {
            chain_cs,
            frost_pubkey_package: Some(self.pub_key_package.clone()),
            ..Default::default()
        };
        self.store.append_changeset(&cs)?;
        Ok(())
    }

    pub fn next_address(&self) -> Result<Address, Box<dyn Error>> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let xonly_pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &self.pub_key_package.verifying_key().serialize().unwrap()
        )?;

        // Create P2TR address directly
        let address = Address::p2tr(&secp, xonly_pk, None, NETWORK);

        // Set the network if needed
        Ok(address)
    }

    /// Sign a transaction using FROST
    /// This method initializes the FROST participant if needed and properly signs
    /// Taproot inputs using the FROST threshold signature scheme
    pub async fn sign_transaction(
        &mut self,
        mut tx: Transaction,
        signers: Vec<Identifier>,
        input_indices: Option<Vec<usize>>
    ) -> Result<Transaction, Box<dyn Error>> {
        // Determine which inputs to sign (all by default)
        let indices_to_sign = match input_indices {
            Some(indices) => indices,
            None => (0..tx.input.len()).collect()
        };

        // Get UTXOs for proper sighash calculation
        let outpoints = self.tx_graph.index.outpoints().into_iter().map(|((_, _), op)| ((), *op));
        let graph = self.tx_graph.graph();
        let tip = self.tip();
        let chain = &self.chain;

        // Collect UTXOs into a Vec so we can search them multiple times
        let utxos: Vec<_> = graph.filter_chain_unspents(chain, tip, outpoints).collect();

        // Create prevouts array for sighash calculation
        let mut prevouts = Vec::new();
        for input in &tx.input {
            let utxo = utxos.iter()
                .find(|(_, u)| u.outpoint == input.previous_output)
                .ok_or_else(|| format!("Could not find UTXO for input {}", input.previous_output))?;
            prevouts.push(utxo.1.txout.clone());
        }

        // Calculate sighashes for all inputs we need to sign
        let mut sighashes = Vec::new();
        {
            let mut sighash_cache = SighashCache::new(&tx);

            for &input_idx in &indices_to_sign {
                if input_idx >= tx.input.len() {
                    return Err(format!("Input index {} out of bounds for tx with {} inputs",
                                       input_idx, tx.input.len()).into());
                }

                let sighash = sighash_cache.taproot_key_spend_signature_hash(
                    input_idx,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default
                )?;
                sighashes.push((input_idx, sighash));
            }
        }

        // Now handle the signing with coordinator in a separate scope
        let signatures = {
            let coordinator = self.coordinator.as_mut()
                .ok_or("Coordinator not connected")?;

            let mut signatures = Vec::new();
            for (input_idx, sighash) in sighashes {
                let frost_signature = coordinator.coordinate_signing(
                    sighash.to_byte_array().to_vec(),
                    signers.clone()
                ).await?;

                let mut taproot_sig = frost_signature.serialize().unwrap();
                if taproot_sig.len() == 64 {
                    taproot_sig.push(0x01); // SIGHASH_ALL flag
                }
                signatures.push((input_idx, taproot_sig));
            }
            signatures
        };

        // Update the transaction witnesses
        for (input_idx, taproot_sig) in signatures {
            tx.input[input_idx].witness.clear();
            tx.input[input_idx].witness.push(taproot_sig.as_slice());
        }

        Ok(tx)
    }

    pub fn print_info(&self) -> Result<(), Box<dyn Error>> {
        let next_addr = self.next_address()?;
        let outpoints = self.tx_graph.index.outpoints().into_iter().map(|((_, _), op)| ((), *op));
        let graph = self.tx_graph.graph();
        let balance = graph.balance(&self.chain, self.tip(), outpoints.clone(), |_, _| true);
        let utxos = graph.filter_chain_unspents(&self.chain, self.tip(), outpoints);
        let txs = graph.full_txs().map(|tx| {
            (tx.txid, graph.get_chain_position(&self.chain, self.tip(), tx.txid))
        });

        println!("Wallet info:");
        println!("      Next address: {}.", next_addr);
        println!("      Balance (confirmed + unconfirmed): {}.", balance.trusted_spendable());
        print!("      Utxos: ");
        for (_, utxo) in utxos {
            print!("{} ({}), ", utxo.outpoint, utxo.txout.value);
        }
        print!("\n      Transactions: ");
        for (txid, pos) in txs {
            print!("{} (chain pos: {:?}), ", txid, pos);
        }
        println!();
        Ok(())
    }

    fn store_frost_data(&mut self) -> Result<(), Box<dyn Error>> {
        let cs = ChangeSet {
            frost_pubkey_package: Some(self.pub_key_package.clone()),
            ..Default::default()
        };
        self.store.append_changeset(&cs)?;
        Ok(())
    }

    // Factory method to create a wallet from key files
    pub fn from_pubkey_file(
        pub_key_package_path: &str,
        store_path: Option<&str>
    ) -> Result<Self, Box<dyn Error>> {
        // Load public key package
        let pub_key_package_data = std::fs::read(pub_key_package_path)?;
        let pub_key_package: PublicKeyPackage = bincode::deserialize(&pub_key_package_data)?;

        // Create wallet with loaded keys
        Self::new(pub_key_package, store_path)
    }
}