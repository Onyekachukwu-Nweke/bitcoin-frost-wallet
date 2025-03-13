use crate::common::errors::{FrostWalletError, Result};
use bitcoin::{
    Address, Network, Transaction, Amount, Txid, Block, BlockHash, transaction::Version,
    Witness, absolute::LockTime, ScriptBuf, secp256k1::XOnlyPublicKey
};
use serde::{Serialize, Deserialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::net::UnixStream;
use futures_util::io::AsyncReadExt;
use capnp::message::{Builder, HeapAllocator};
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use serde_json::Value;
use log::{debug, info, warn, error};

// Define interface for Bitcoin RPC operations
#[async_trait]
pub trait BitcoinRpcClient: Send + Sync {
    /// Get network info
    async fn get_network_info(&self) -> Result<NetworkInfo>;

    /// Get blockchain info
    async fn get_blockchain_info(&self) -> Result<BlockchainInfo>;

    /// Get wallet balance
    async fn get_balance(&self) -> Result<Amount>;

    /// Get unspent transaction outputs
    async fn get_utxos(&self, min_conf: Option<u32>, max_conf: Option<u32>) -> Result<Vec<Utxo>>;

    /// Get raw transaction
    async fn get_raw_transaction(&self, txid: &str) -> Result<Transaction>;

    /// Send raw transaction
    async fn send_raw_transaction(&self, tx_hex: &str) -> Result<Txid>;

    /// Import address to the wallet
    async fn import_address(&self, address: &str, label: Option<&str>, rescan: bool) -> Result<()>;
}

/// Network information from Bitcoin node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub version: u64,
    pub subversion: String,
    pub connections: u32,
    pub network: Network,
}

/// Blockchain information from Bitcoin node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    pub best_block_hash: BlockHash,
    pub difficulty: f64,
    pub verification_progress: f64,
    pub chain_work: String,
}

/// Unspent transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub script_pub_key: String,
    pub amount: Amount,
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
    pub safe: bool,
}

/// Implementation of Bitcoin RPC client using JSON-RPC directly
pub struct BitcoinRpcClientImpl {
    url: String,
    auth: String,
    network: Network,
    client: reqwest::Client,
}

impl BitcoinRpcClientImpl {
    /// Create a new RPC client with authentication
    pub fn new(url: &str, username: &str, password: &str, network: Network) -> Self {
        let auth = format!("{}:{}", username, password);

        Self {
            url: url.to_string(),
            auth: base64::encode(auth),
            network,
            client: reqwest::Client::new(),
        }
    }

    /// Create a new RPC client with cookie file
    pub fn with_cookie_file(url: &str, cookie_file: impl AsRef<Path>, network: Network) -> Result<Self> {
        let cookie = std::fs::read_to_string(cookie_file.as_ref())
            .map_err(|e| FrostWalletError::IoError(e))?;

        Ok(Self {
            url: url.to_string(),
            auth: base64::encode(cookie),
            network,
            client: reqwest::Client::new(),
        })
    }

    /// Send RPC request
    async fn send_request<T: for<'de> Deserialize<'de>>(&self, method: &str, params: Vec<serde_json::Value>) -> Result<T> {
        let request = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "frost-wallet",
            "method": method,
            "params": params
        });

        let response = self.client.post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth))
            .json(&request)
            .send()
            .await
            .map_err(|e| FrostWalletError::BitcoinRpcError(format!("Request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await
            .map_err(|e| FrostWalletError::BitcoinRpcError(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            return Err(FrostWalletError::BitcoinRpcError(format!("RPC request failed with status {}: {}", status, response_text)));
        }

        let response: RpcResponse<T> = serde_json::from_str(&response_text)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize response: {}", e)))?;

        match (response.error, response.result) {
            (Some(error), _) => Err(FrostWalletError::BitcoinRpcError(format!("RPC error: {}", error))),
            (None, Some(result)) => Ok(result),
            _ => Err(FrostWalletError::BitcoinRpcError("Invalid RPC response".to_string())),
        }
    }
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct NetworkInfoResponse {
    version: u64,
    subversion: String,
    connections: u32,
}

#[derive(Deserialize)]
struct BlockchainInfoResponse {
    chain: String,
    blocks: u32,
    headers: u32,
    bestblockhash: String,
    difficulty: f64,
    verificationprogress: f64,
    chainwork: String,
}

#[derive(Deserialize)]
struct ListUnspentResponse {
    txid: String,
    vout: u32,
    address: Option<String>,
    scriptPubKey: String,
    amount: f64,
    confirmations: u32,
    spendable: bool,
    solvable: bool,
    safe: bool,
}

#[async_trait]
impl BitcoinRpcClient for BitcoinRpcClientImpl {
    async fn get_network_info(&self) -> Result<NetworkInfo> {
        let response: NetworkInfoResponse = self.send_request("getnetworkinfo", vec![]).await?;

        Ok(NetworkInfo {
            version: response.version,
            subversion: response.subversion,
            connections: response.connections,
            network: self.network,
        })
    }

    async fn get_blockchain_info(&self) -> Result<BlockchainInfo> {
        let response: BlockchainInfoResponse = self.send_request("getblockchaininfo", vec![]).await?;

        Ok(BlockchainInfo {
            chain: response.chain,
            blocks: response.blocks,
            headers: response.headers,
            best_block_hash: BlockHash::from_str(&response.bestblockhash)
                .map_err(|e| FrostWalletError::BitcoinError(format!("Invalid block hash: {}", e)))?,
            difficulty: response.difficulty,
            verification_progress: response.verificationprogress,
            chain_work: response.chainwork,
        })
    }

    async fn get_balance(&self) -> Result<Amount> {
        let balance: f64 = self.send_request("getbalance", vec![]).await?;

        // Convert BTC to satoshis
        let satoshis = (balance * 100_000_000.0) as u64;
        Ok(Amount::from_sat(satoshis))
    }

    async fn get_utxos(&self, min_conf: Option<u32>, max_conf: Option<u32>) -> Result<Vec<Utxo>> {
        let min_conf_value = serde_json::to_value(min_conf.unwrap_or(1))
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize min_conf: {}", e)))?;

        let max_conf_value = match max_conf {
            Some(max) => serde_json::to_value(max)
                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize max_conf: {}", e)))?,
            None => serde_json::Value::Null,
        };

        let list_unspent: Vec<ListUnspentResponse> = self.send_request(
            "listunspent",
            vec![min_conf_value, max_conf_value]
        ).await?;

        let utxos = list_unspent.into_iter()
            .map(|utxo| Utxo {
                txid: utxo.txid,
                vout: utxo.vout,
                address: utxo.address.unwrap_or_default(),
                script_pub_key: utxo.scriptPubKey,
                amount: Amount::from_sat((utxo.amount * 100_000_000.0) as u64),
                confirmations: utxo.confirmations,
                spendable: utxo.spendable,
                solvable: utxo.solvable,
                safe: utxo.safe,
            })
            .collect();

        Ok(utxos)
    }

    async fn get_raw_transaction(&self, txid: &str) -> Result<Transaction> {
        let txid_value = serde_json::to_value(txid)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize txid: {}", e)))?;

        let verbose_value = serde_json::to_value(false)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize verbose flag: {}", e)))?;

        let tx_hex: String = self.send_request("getrawtransaction", vec![txid_value, verbose_value]).await?;

        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to decode transaction hex: {}", e)))?;

        bitcoin::consensus::encode::deserialize(&tx_bytes)
            .map_err(|e| FrostWalletError::BitcoinError(format!("Failed to deserialize transaction: {}", e)))
    }

    async fn send_raw_transaction(&self, tx_hex: &str) -> Result<Txid> {
        let tx_hex_value = serde_json::to_value(tx_hex)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize tx_hex: {}", e)))?;

        let txid_str: String = self.send_request("sendrawtransaction", vec![tx_hex_value]).await?;

        Txid::from_str(&txid_str)
            .map_err(|e| FrostWalletError::BitcoinError(format!("Invalid txid: {}", e)))
    }

    async fn import_address(&self, address: &str, label: Option<&str>, rescan: bool) -> Result<()> {
        let address_value = serde_json::to_value(address)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize address: {}", e)))?;

        let label_value = serde_json::to_value(label.unwrap_or(""))
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize label: {}", e)))?;

        let rescan_value = serde_json::to_value(rescan)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize rescan flag: {}", e)))?;

        let _: () = self.send_request("importaddress", vec![address_value, label_value, rescan_value]).await?;

        Ok(())
    }
}

/// Mock implementation of Bitcoin RPC client for testing
#[cfg(test)]
#[derive(Clone)]
pub struct MockBitcoinRpcClient {
    network: Network,
    utxos: Vec<Utxo>,
    transactions: std::collections::HashMap<String, Transaction>,
}

#[cfg(test)]
impl MockBitcoinRpcClient {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            utxos: Vec::new(),
            transactions: std::collections::HashMap::new(),
        }
    }

    pub fn add_utxo(&mut self, utxo: Utxo) {
        self.utxos.push(utxo);
    }

    pub fn add_transaction(&mut self, tx: Transaction) {
        self.transactions.insert(tx.txid().to_string(), tx);
    }
}

#[cfg(test)]
#[async_trait]
impl BitcoinRpcClient for MockBitcoinRpcClient {
    async fn get_network_info(&self) -> Result<NetworkInfo> {
        Ok(NetworkInfo {
            version: 210000,
            subversion: "/Satoshi:21.0.0/".to_string(),
            connections: 8,
            network: self.network,
        })
    }

    async fn get_blockchain_info(&self) -> Result<BlockchainInfo> {
        Ok(BlockchainInfo {
            chain: match self.network {
                Network::Bitcoin => "main".to_string(),
                Network::Testnet => "test".to_string(),
                Network::Regtest => "regtest".to_string(),
                _ => "unknown".to_string(),
            },
            blocks: 100,
            headers: 100,
            best_block_hash: BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap(),
            difficulty: 1.0,
            verification_progress: 1.0,
            chain_work: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        })
    }

    async fn get_balance(&self) -> Result<Amount> {
        let total: u64 = self.utxos.iter()
            .map(|utxo| utxo.amount.to_sat())
            .sum();

        Ok(Amount::from_sat(total))
    }

    async fn get_utxos(&self, min_conf: Option<u32>, max_conf: Option<u32>) -> Result<Vec<Utxo>> {
        let min_conf = min_conf.unwrap_or(0);
        let max_conf = max_conf.unwrap_or(9_999_999);

        let filtered_utxos = self.utxos.iter()
            .filter(|utxo| utxo.confirmations >= min_conf && utxo.confirmations <= max_conf)
            .cloned()
            .collect();

        Ok(filtered_utxos)
    }

    async fn get_raw_transaction(&self, txid: &str) -> Result<Transaction> {
        match self.transactions.get(txid) {
            Some(tx) => Ok(tx.clone()),
            None => Err(FrostWalletError::BitcoinRpcError(format!("Transaction not found: {}", txid))),
        }
    }

    async fn send_raw_transaction(&self, tx_hex: &str) -> Result<Txid> {
        let tx_bytes = hex::decode(tx_hex)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to decode transaction hex: {}", e)))?;

        let tx: Transaction = bitcoin::consensus::encode::deserialize(&tx_bytes)
            .map_err(|e| FrostWalletError::BitcoinError(format!("Failed to deserialize transaction: {}", e)))?;

        Ok(tx.txid())
    }

    async fn import_address(&self, _address: &str, _label: Option<&str>, _rescan: bool) -> Result<()> {
        // No-op for mock
        Ok(())
    }
}

/// CapnProto RPC service for Bitcoin FROST wallet
pub struct CapnpBitcoinRpcService {
    rpc_client: Arc<dyn BitcoinRpcClient>,
}

impl CapnpBitcoinRpcService {
    pub fn new(rpc_client: Arc<dyn BitcoinRpcClient>) -> Self {
        Self { rpc_client }
    }

    pub async fn start(self, socket_path: impl AsRef<Path>) -> Result<()> {
        let socket_path = socket_path.as_ref().to_path_buf();

        // Remove existing socket if it exists
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)
                .map_err(|e| FrostWalletError::IoError(e))?;
        }

        // Create Unix socket listener
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .map_err(|e| FrostWalletError::IoError(e))?;

        info!("CapnProto RPC service started on {}", socket_path.display());

        // Accept connections
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let rpc_client = self.rpc_client.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, rpc_client).await {
                            error!("Error handling RPC connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(stream: UnixStream, rpc_client: Arc<dyn BitcoinRpcClient>) -> Result<()> {
        use futures_util::io::AsyncReadExt;

        // Setup CapnProto RPC
        let stream = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream);
        let (reader, writer) = futures_util::io::AsyncReadExt::split(stream);

        let network = twoparty::VatNetwork::new(
            reader,
            writer,
            rpc_twoparty_capnp::Side::Server,
            Default::default(),
        );

        // TODO: Create CapnProto service for wallet operations

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{OutPoint, TxIn, TxOut};

    #[tokio::test]
    async fn test_mock_bitcoin_rpc_client() {
        // Create a mock RPC client with testnet network
        let mut mock_client = MockBitcoinRpcClient::new(Network::Testnet);

        // Add some UTXOs
        mock_client.add_utxo(Utxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            vout: 0,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pub_key: "00140000000000000000000000000000000000000001".to_string(),
            amount: Amount::from_sat(100_000),
            confirmations: 6,
            spendable: true,
            solvable: true,
            safe: true,
        });

        mock_client.add_utxo(Utxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
            vout: 1,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pub_key: "00140000000000000000000000000000000000000001".to_string(),
            amount: Amount::from_sat(50_000),
            confirmations: 3,
            spendable: true,
            solvable: true,
            safe: true,
        });

        // Test network info
        let network_info = mock_client.get_network_info().await.unwrap();
        assert_eq!(network_info.network, Network::Testnet);

        // Test balance
        let balance = mock_client.get_balance().await.unwrap();
        assert_eq!(balance.to_sat(), 150_000);

        // Test UTXOs with min confirmations
        let utxos = mock_client.get_utxos(Some(5), None).await.unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, "0000000000000000000000000000000000000000000000000000000000000001");

        // Create a transaction for testing
        let txid1 = Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(txid1, 0),
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence(0xFFFFFFFF),
                    witness: Witness::new(),
                },
            ],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::new(),
                },
            ],
        };

        // Add the transaction to the mock client
        mock_client.add_transaction(tx.clone());

        // Test get transaction - make sure we use the txid string representation
        let txid_str = tx.txid().to_string();
        let retrieved_tx = mock_client.get_raw_transaction(&txid_str).await.unwrap();

        // Verify the retrieved transaction matches the original
        assert_eq!(retrieved_tx.txid(), tx.txid());

        // Test sending a transaction
        let tx_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx));
        let sent_txid = mock_client.send_raw_transaction(&tx_hex).await.unwrap();
        assert_eq!(sent_txid, tx.txid());
    }
}