use crate::wallet::{rpc::RpcInterface, core::BdkFrostWallet};
use std::sync::{Arc, Mutex};
use std::error::Error;
use frost_secp256k1::keys::PublicKeyPackage;
use crate::common::types::ThresholdConfig;

async fn wallet_startup_complete(
    rpc: &RpcInterface,
    wallet: BdkFrostWallet,
) -> Arc<Mutex<BdkFrostWallet>> {
    println!("BDK FROST Wallet is synced with bitcoin-node.");
    rpc.show_progress("BDK FROST Wallet startup", 100, true).await;
    let wallet = Arc::new(Mutex::new(wallet));
    rpc.register_notifications(wallet.clone()).await;
    wallet
}

async fn wallet_handle_startup_reorg(
    rpc: &RpcInterface,
    mut wallet: BdkFrostWallet,
    node_tip: &bdk_chain::BlockId,
    wallet_tip: &bdk_chain::BlockId,
) -> Arc<Mutex<BdkFrostWallet>> {
    let common_ancestor = rpc.common_ancestor(&node_tip.hash, &wallet_tip.hash)
        .await
        .unwrap_or_else(|| bdk_chain::BlockId {
            height: 0,
            hash: wallet.genesis_hash(),
        });

    println!("Disconnecting the chain from {:?}", common_ancestor);
    wallet.disconnect(common_ancestor).unwrap();

    let start_height: i32 = common_ancestor.height.try_into().expect("Never negative.");
    for h in start_height..=node_tip.height.try_into().expect("Never negative.") {
        let block = rpc.get_block(&node_tip.hash, h).await;
        wallet.apply_block(&block, h).unwrap();
    }

    wallet_startup_complete(rpc, wallet).await
}

pub async fn wallet_startup(
    rpc: &RpcInterface,
    coordinator_addr: std::net::SocketAddr,
    pub_key_package: PublicKeyPackage,
    store_path: Option<&str>,
) -> Result<Arc<Mutex<BdkFrostWallet>>, Box<dyn Error>> {
    let mut wallet = BdkFrostWallet::new(pub_key_package, store_path).unwrap();
    rpc.show_progress("BDK FROST Wallet startup", 1, false).await;

    let node_tip = rpc.get_tip().await;
    let wallet_tip = wallet.tip();
    if wallet_tip == node_tip {
        return Ok(wallet_startup_complete(rpc, wallet).await);
    }

    if wallet_tip.height >= node_tip.height {
        println!("The tip on bitcoin-node was reorged or moved backward.");
        return Ok(wallet_handle_startup_reorg(rpc, wallet, &node_tip, &wallet_tip).await);
    }

    println!("Height on bitcoin-node moved forward. Checking if wallet tip is in best chain.");
    if !rpc.is_in_best_chain(&node_tip.hash, &wallet_tip.hash).await {
        println!("Wallet tip is not in best chain anymore. Processing reorg.");
        return Ok(wallet_handle_startup_reorg(rpc, wallet, &node_tip, &wallet_tip).await);
    }

    let start_height: i32 = (wallet_tip.height + 1).try_into().expect("Must fit");
    if !rpc.has_blocks(&node_tip.hash, start_height).await {
        return Err("bitcoin-node is missing blocks to sync the BDK wallet.".into());
    }

    println!("Syncing BDK FROST Wallet.");
    for h in start_height..=node_tip.height.try_into().expect("Never negative.") {
        let block = rpc.get_block(&node_tip.hash, h).await;
        wallet.apply_block(&block, h)?;
    }

    println!("Done syncing missing blocks.");
    Ok(wallet_startup_complete(rpc, wallet).await)
}