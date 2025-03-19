use bdk_chain::{
    bitcoin::{self, Address, Network, Transaction},
    keychain_txout::KeychainTxOutIndex,
    local_chain::LocalChain,
    BlockId, CheckPoint, ConfirmationBlockTime, IndexedTxGraph, Merge,
};
use bdk_file_store::Store as BdkStore;
use frost_secp256k1::{Identifier, Signature, VerifyingKey, keys::{KeyPackage, PublicKeyPackage}};
use std::sync::{Arc, Mutex};
use std::error::Error;
use crate::common::types::ThresholdConfig;
use crate::frost::coordinator::CoordinatorController;
use crate::frost::participant::FrostParticipant;

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
    pub frost_key_package: Option<KeyPackage>,
    pub frost_pubkey_package: Option<PublicKeyPackage>,
}

impl Merge for ChangeSet {
    fn merge(&mut self, other: Self) {
        Merge::merge(&mut self.chain_cs, other.chain_cs);
        Merge::merge(&mut self.graph_cs, other.graph_cs);
        if self.frost_key_package.is_none() {
            self.frost_key_package = other.frost_key_package;
        }
        if self.frost_pubkey_package.is_none() {
            self.frost_pubkey_package = other.frost_pubkey_package;
        }
    }

    fn is_empty(&self) -> bool {
        self.chain_cs.is_empty() && self.graph_cs.is_empty() &&
            self.frost_key_package.is_none() && self.frost_pubkey_package.is_none()
    }
}

pub struct BdkFrostWallet {
    pub chain: LocalChain,
    pub tx_graph: IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<()>>,
    pub store: BdkStore<ChangeSet>,
    pub participant: FrostParticipant,
    pub coordinator: Option<CoordinatorController>,
    pub local_id: Identifier,
    pub key_package: KeyPackage,
    pub pub_key_package: PublicKeyPackage,
}

impl BdkFrostWallet {
    pub async fn new(
        local_id: Identifier,
        config: ThresholdConfig,
        coordinator_addr: std::net::SocketAddr,
    ) -> Result<Self, Box<dyn Error>> {
        let (mut chain, _) = LocalChain::from_genesis_hash(
            bitcoin::constants::genesis_block(NETWORK).block_hash()
        );
        let mut index = KeychainTxOutIndex::default();
        let mut store = BdkStore::open_or_create_new(BDK_STORE_MAGIC, BDK_STORE_PATH)?;

        let mut dkg_participant = DkgParticipantProcess::new(local_id, config.clone());
        dkg_participant.connect_to_coordinator(coordinator_addr).await?;
        let key_package = dkg_participant.run_dkg().await?;
        let pub_key_package = dkg_participant.get_public_key_package()?;

        let participant = FrostParticipant::new(local_id, key_package.clone(), pub_key_package.clone());

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let xonly_pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &pub_key_package.verifying_key().serialize()?
        )?;
        let taproot_script = TaprootBuilder::new()
            .finalize(&secp, xonly_pk)?
            .script_pubkey();
        index.insert_spk((), taproot_script);

        let mut tx_graph = IndexedTxGraph::new(index);

        for cs in store.iter_changesets() {
            let cs = cs?;
            chain.apply_changeset(&cs.chain_cs)?;
            tx_graph.apply_changeset(cs.graph_cs);
            if let Some(kp) = cs.frost_key_package {
                key_package = kp;
            }
            if let Some(pp) = cs.frost_pubkey_package {
                pub_key_package = pp;
            }
        }

        let mut wallet = Self {
            chain,
            tx_graph,
            store,
            participant,
            coordinator: None,
            local_id,
            key_package,
            pub_key_package,
        };

        if store.iter_changesets().next().is_none() {
            wallet.store_frost_data()?;
        }

        Ok(wallet)
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
            frost_key_package: Some(self.key_package.clone()),
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
            frost_key_package: Some(self.key_package.clone()),
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
                    cs.keys.insert(cp.height(), None);
                }
            }
            self.chain = LocalChain::from_genesis_hash(
                bitcoin::constants::genesis_block(NETWORK).block_hash()
            ).0;
            cs
        };
        let cs = ChangeSet {
            chain_cs,
            frost_key_package: Some(self.key_package.clone()),
            frost_pubkey_package: Some(self.pub_key_package.clone()),
            ..Default::default()
        };
        self.store.append_changeset(&cs)?;
        Ok(())
    }

    pub fn next_address(&self) -> Result<Address, Box<dyn Error>> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let xonly_pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &self.pub_key_package.verifying_key().serialize()?
        )?;
        let script = TaprootBuilder::new().finalize(&secp, xonly_pk)?.script_pubkey();
        Ok(Address::from_script(&script, NETWORK)?)
    }

    pub async fn sign_transaction(&mut self, tx: Transaction, signers: Vec<Identifier>) -> Result<Transaction, Box<dyn Error>> {
        let coordinator = self.coordinator.as_mut()
            .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Coordinator not connected")))?;

        let sighash = vec![0; 32]; // Placeholder: Implement proper Taproot sighash
        let signature = coordinator.coordinate_signing(sighash, signers).await?;

        let mut signed_tx = tx;
        signed_tx.input[0].witness.push(&signature.serialize());
        Ok(signed_tx)
    }

    pub fn connect_coordinator(&mut self, coordinator_id: Identifier, addr: std::net::SocketAddr) -> Result<(), Box<dyn Error>> {
        let mut coordinator = CoordinatorController::new(coordinator_id, ThresholdConfig {
            threshold: 2,
            total_participants: 3,
        }, addr.port());
        coordinator.set_public_key_package(self.pub_key_package.clone())?;
        self.coordinator = Some(coordinator);
        Ok(())
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
            frost_key_package: Some(self.key_package.clone()),
            frost_pubkey_package: Some(self.pub_key_package.clone()),
            ..Default::default()
        };
        self.store.append_changeset(&cs)?;
        Ok(())
    }
}