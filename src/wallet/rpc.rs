// src/bdk_frost_wallet/rpc.rs

use bdk_chain::bitcoin;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use tokio::task::{self, JoinHandle};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use crate::wallet::core::BdkFrostWallet;
use std::sync::{Arc, Mutex};
use std::error::Error;
use bdk_chain::bitcoin::consensus::Decodable;
use bdk_chain::bitcoin::hashes::Hash;
use crate::{chain_capnp, init_capnp, proxy_capnp};

pub struct RpcInterface {
    rpc_handle: JoinHandle<Result<(), capnp::Error>>,
    disconnector: capnp_rpc::Disconnector<twoparty::VatId>,
    thread: proxy_capnp::thread::Client,
    chain_interface: chain_capnp::chain::Client,
}

impl RpcInterface {
    pub async fn new(stream: tokio::net::UnixStream) -> Result<Self, Box<dyn Error>> {
        let (reader, writer) = stream.into_split();
        let network = Box::new(twoparty::VatNetwork::new(
            reader.compat(),
            writer.compat_write(),
            rpc_twoparty_capnp::Side::Client,
            Default::default(),
        ));

        let mut rpc = RpcSystem::new(network, None);
        let init_interface: init_capnp::init::Client = rpc.bootstrap(rpc_twoparty_capnp::Side::Server);
        let disconnector = rpc.get_disconnector();
        let rpc_handle = task::spawn_local(rpc);

        let mk_init_req = init_interface.construct_request();
        let response = mk_init_req.send().promise.await?;
        let thread_map = response.get()?.get_thread_map()?;

        let mk_thread_req = thread_map.make_thread_request();
        let response = mk_thread_req.send().promise.await?;
        let thread = response.get()?.get_result()?;

        let mut mk_chain_req = init_interface.make_chain_request();
        mk_chain_req.get().get_context()?.set_thread(thread.clone());
        let response = mk_chain_req.send().promise.await?;
        let chain_interface = response.get()?.get_result()?;

        let mut mk_mess_req = chain_interface.init_message_request();
        mk_mess_req.get().get_context()?.set_thread(thread.clone());
        mk_mess_req.get().set_message("FROST BDK Wallet initializing...");
        let _ = mk_mess_req.send().promise.await?;

        Ok(Self {
            rpc_handle,
            thread,
            chain_interface,
            disconnector,
        })
    }

    pub async fn get_tip(&self) -> bdk_chain::BlockId {
        let mut height_req = self.chain_interface.get_height_request();
        height_req.get().get_context().unwrap().set_thread(self.thread.clone());
        let response = height_req.send().promise.await.unwrap();
        let height_i32 = response.get().unwrap().get_result();
        let height = height_i32.try_into().expect("Height is never negative.");

        let mut hash_req = self.chain_interface.get_block_hash_request();
        hash_req.get().get_context().unwrap().set_thread(self.thread.clone());
        hash_req.get().set_height(height_i32);
        let response = hash_req.send().promise.await.unwrap();
        let hash = bitcoin::BlockHash::from_slice(response.get().unwrap().get_result().unwrap())
            .expect("Core must be serving valid hashes.");

        bdk_chain::BlockId { height, hash }
    }

    pub async fn is_in_best_chain(&self, node_tip_hash: &bitcoin::BlockHash, ancestor: &bitcoin::BlockHash) -> bool {
        let mut find_req = self.chain_interface.find_ancestor_by_hash_request();
        find_req.get().get_context().unwrap().set_thread(self.thread.clone());
        find_req.get().set_block_hash(node_tip_hash.as_ref());
        find_req.get().set_ancestor_hash(ancestor.as_ref());
        let response = find_req.send().promise.await.unwrap();
        response.get().unwrap().get_result()
    }

    pub async fn has_blocks(&self, node_tip_hash: &bitcoin::BlockHash, start_height: i32) -> bool {
        let mut has_blocks_req = self.chain_interface.has_blocks_request();
        has_blocks_req.get().get_context().unwrap().set_thread(self.thread.clone());
        has_blocks_req.get().set_block_hash(node_tip_hash.as_ref());
        has_blocks_req.get().set_min_height(start_height);
        let response = has_blocks_req.send().promise.await.unwrap();
        response.get().unwrap().get_result()
    }

    pub async fn get_block(&self, node_tip_hash: &bitcoin::BlockHash, height: i32) -> bitcoin::Block {
        let mut find_req = self.chain_interface.find_ancestor_by_height_request();
        find_req.get().get_context().unwrap().set_thread(self.thread.clone());
        find_req.get().set_block_hash(node_tip_hash.as_ref());
        find_req.get().set_ancestor_height(height);
        find_req.get().get_ancestor().unwrap().set_want_data(true);
        let response = find_req.send().promise.await.unwrap();
        bitcoin::Block::consensus_decode(
            &mut response.get().unwrap().get_ancestor().unwrap().get_data().unwrap()
        ).expect("Core must provide valid blocks")
    }

    pub async fn common_ancestor(&self, node_tip_hash: &bitcoin::BlockHash, wallet_tip_hash: &bitcoin::BlockHash) -> Option<bdk_chain::BlockId> {
        let mut find_req = self.chain_interface.find_common_ancestor_request();
        find_req.get().get_context().unwrap().set_thread(self.thread.clone());
        find_req.get().set_block_hash1(node_tip_hash.as_ref());
        find_req.get().set_block_hash1(wallet_tip_hash.as_ref());
        find_req.get().get_ancestor().unwrap().set_want_height(true);
        find_req.get().get_ancestor().unwrap().set_want_hash(true);
        let response = find_req.send().promise.await.unwrap();
        let response = response.get().unwrap();
        let ancestor = response.get_ancestor().unwrap();
        if !ancestor.get_found() {
            return None;
        }
        let height = ancestor.get_height().try_into().expect("Can't be negative.");
        let hash = bitcoin::BlockHash::from_slice(ancestor.get_hash().unwrap())
            .expect("Core must provide valid blocks");
        Some(bdk_chain::BlockId { height, hash })
    }

    pub async fn show_progress(&self, title: &str, progress: i32, resume_possible: bool) {
        let mut mk_mess_req = self.chain_interface.show_progress_request();
        mk_mess_req.get().get_context().unwrap().set_thread(self.thread.clone());
        mk_mess_req.get().set_title(title);
        mk_mess_req.get().set_progress(progress);
        mk_mess_req.get().set_resume_possible(resume_possible);
        let _ = mk_mess_req.send().promise.await.unwrap();
    }

    pub async fn register_notifications(&self, wallet: Arc<Mutex<BdkFrostWallet>>) {
        let notif_handler = capnp_rpc::new_client(wallet);
        let mut register_req = self.chain_interface.handle_notifications_request();
        register_req.get().get_context().unwrap().set_thread(self.thread.clone());
        register_req.get().set_notifications(notif_handler);
        let _ = register_req.send().promise.await.unwrap();
    }

    pub async fn disconnect(self) -> Result<(), capnp::Error> {
        self.disconnector.await.unwrap();
        self.rpc_handle.await.unwrap()
    }
}

impl chain_capnp::chain_notifications::Server for Arc<Mutex<BdkFrostWallet>> {
    fn destroy(&mut self, _: chain_capnp::chain_notifications::DestroyParams, _: chain_capnp::chain_notifications::DestroyResults) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        unimplemented!("Destroy notification")
    }

    fn transaction_added_to_mempool(
        &mut self,
        params: chain_capnp::chain_notifications::TransactionAddedToMempoolParams,
        _: chain_capnp::chain_notifications::TransactionAddedToMempoolResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let tx = bitcoin::Transaction::consensus_decode(&mut capnp_rpc::pry!(capnp_rpc::pry!(params.get()).get_tx()))
            .expect("Core must provide valid transactions.");
        let txid = tx.compute_txid();
        println!("New mempool transaction {}.", txid);
        if let Err(e) = self.lock().unwrap().apply_tx(tx) {
            eprintln!("Error applying tx {} to wallet: {}", txid, e);
        }
        ::capnp::capability::Promise::ok(())
    }

    fn transaction_removed_from_mempool(
        &mut self,
        _: chain_capnp::chain_notifications::TransactionRemovedFromMempoolParams,
        _: chain_capnp::chain_notifications::TransactionRemovedFromMempoolResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        ::capnp::capability::Promise::ok(())
    }

    fn block_connected(
        &mut self,
        params: chain_capnp::chain_notifications::BlockConnectedParams,
        _: chain_capnp::chain_notifications::BlockConnectedResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let info = capnp_rpc::pry!(capnp_rpc::pry!(params.get()).get_block());
        let height = info.get_height();
        let block = bitcoin::Block::consensus_decode(&mut capnp_rpc::pry!(info.get_data()))
            .expect("Core must provide valid transactions.");
        println!("New connected block {}.", block.block_hash());
        if let Err(e) = self.lock().unwrap().apply_block(&block, height) {
            eprintln!("Error when applying connected block {}: '{}'", block.block_hash(), e);
        }
        ::capnp::capability::Promise::ok(())
    }

    fn block_disconnected(
        &mut self,
        params: chain_capnp::chain_notifications::BlockDisconnectedParams,
        _: chain_capnp::chain_notifications::BlockDisconnectedResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let info = capnp_rpc::pry!(capnp_rpc::pry!(params.get()).get_block());
        let height: u32 = info.get_height().try_into().expect("Can't be negative.");
        let hash = bitcoin::BlockHash::from_slice(capnp_rpc::pry!(info.get_hash()))
            .expect("Core must provide valid block hashes");
        self.lock().unwrap().disconnect(bdk_chain::BlockId { height, hash })
            .expect("Core will not disconnect genesis block.");
        println!("Disconnected block {}", hash);
        ::capnp::capability::Promise::ok(())
    }

    fn updated_block_tip(
        &mut self,
        _: chain_capnp::chain_notifications::UpdatedBlockTipParams,
        _: chain_capnp::chain_notifications::UpdatedBlockTipResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        println!("Block tip updated.");
        ::capnp::capability::Promise::ok(())
    }

    fn chain_state_flushed(
        &mut self,
        _: chain_capnp::chain_notifications::ChainStateFlushedParams,
        _: chain_capnp::chain_notifications::ChainStateFlushedResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        println!("Chainstate flushed.");
        ::capnp::capability::Promise::ok(())
    }
}