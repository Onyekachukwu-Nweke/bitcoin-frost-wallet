use crate::common::errors::{FrostWalletError, Result};
use bitcoin::{Transaction, Txid};
use capnp::message::{Builder, HeapAllocator};
use capnp_rpc::{RpcSystem, twoparty, rpc_twoparty_capnp};
use std::net::SocketAddr;
use tokio::net::UnixStream;

// Import generated Cap'n Proto code
use crate::capnp_gen::wallet_capnp::{bitcoin_wallet, transaction, transaction_request};

pub struct NodeClient {
    /// Cap'n Proto RPC system
    rpc_system: RpcSystem<rpc_twoparty_capnp::Side>,
    /// Bitcoin wallet client from Cap'n Proto
    wallet_client: bitcoin_wallet::Client,
}

impl NodeClient {
    /// Connect to Bitcoin node via Unix socket
    pub fn connect() -> Result<Self> {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            // Connect to Unix socket
            let socket_path = "/tmp/bitcoin_wallet.sock"; // Make configurable
            let stream = UnixStream::connect(socket_path).await
                .map_err(|e| FrostWalletError::IoError(e))?;

            // Set up Cap'n Proto RPC
            let (reader, writer) = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream).split();
            let network = twoparty::VatNetwork::new(
                reader,
                writer,
                rpc_twoparty_capnp::Side::Client,
                Default::default(),
            );

            let mut rpc_system = RpcSystem::new(Box::new(network), None);
            let wallet_client: bitcoin_wallet::Client = rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);

            // Run RPC system in the background
            tokio::spawn(async move {
                rpc_system.await
                    .map_err(|e| FrostWalletError::IpcError(format!("RPC error: {}", e)))
            });

            Ok(Self {
                rpc_system,
                wallet_client,
            })
        })
    }

    /// Broadcast a transaction
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<Txid> {
        // Serialize transaction
        let tx_bytes = bitcoin::consensus::serialize(&tx);

        // Create Cap'n Proto message
        let mut message = Builder::new_default();
        let mut tx_request = message.init_root::<transaction::Builder>();
        tx_request.set_raw_tx(&tx_bytes);

        // Send request
        let response = self.wallet_client.broadcast_transaction(
            tx_request.into_reader()
        ).await.map_err(|e| FrostWalletError::IpcError(format!("RPC error: {}", e)))?;

        // Parse response
        let result = response.get_result().map_err(|e|
            FrostWalletError::SerializationError(format!("Failed to get result: {}", e))
        )?;

        if !result.get_success() {
            return Err(FrostWalletError::SerializationError(format!(
                "Failed to broadcast transaction: {}",
                result.get_error().map_err(|e|
                    FrostWalletError::SerializationError(format!("Failed to get error: {}", e))
                )?
            )));
        }

        // Parse txid
        let txid_str = result.get_value().map_err(|e|
            FrostWalletError::SerializationError(format!("Failed to get txid: {}", e))
        )?;

        let txid: Txid = txid_str.parse().map_err(|e|
            FrostWalletError::SerializationError(format!("Failed to parse txid: {}", e))
        )?;

        Ok(txid)
    }
}