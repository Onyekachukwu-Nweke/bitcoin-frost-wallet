@0xc2458bc93e12ae11;

using Common = import "common.capnp";
using Dkg = import "dkg.capnp";
using Frost = import "frost.capnp";

enum Network {
  mainnet @0;
  testnet @1;
  regtest @2;
}

struct WalletConfig {
  threshold @0 :Common.ThresholdConfig;
  network @1 :Network;
  storagePath @2 :Text;
}

struct Address {
  value @0 :Text;
  network @1 :Network;
}

struct Transaction {
  txid @0 :Text;
  rawTx @1 :Data;
  inputs @2 :List(TxInput);
  outputs @3 :List(TxOutput);
  fee @4 :UInt64;
}

struct TxInput {
  txid @0 :Text;
  vout @1 :UInt32;
  amount @2 :UInt64;
  address @3 :Text;
  scriptPubKey @4 :Data;
}

struct TxOutput {
  address @0 :Text;
  amount @1 :UInt64;
}

struct TransactionRequest {
  recipientAddress @0 :Text;
  amount @1 :UInt64;
  feeRate @2 :Float64;
}

struct Balance {
  confirmed @0 :UInt64;
  unconfirmed @1 :UInt64;
  immature @2 :UInt64;
  total @3 :UInt64;
}

interface BitcoinWallet {
  # Initialize wallet with configuration
  initialize @0 (context :Common.Context, config :WalletConfig) -> (result :Common.Result(Bool));

  # Set the local key package from DKG
  setKeyPackage @1 (context :Common.Context, keyPackage :Dkg.KeyPackage, pubKeyPackage :Dkg.PublicKeyPackage) -> (result :Common.Result(Bool));

  # Get the wallet address
  getAddress @2 (context :Common.Context) -> (result :Common.Result(Address));

  # Create a transaction
  createTransaction @3 (context :Common.Context, request :TransactionRequest) -> (result :Common.Result(Transaction));

  # Sign a transaction using FROST
  signTransaction @4 (context :Common.Context, tx :Transaction, signers :List(Common.Identifier)) -> (result :Common.Result(Transaction));

  # Broadcast a signed transaction to the network
  broadcastTransaction @5 (context :Common.Context, tx :Transaction) -> (result :Common.Result(Text));

  # Get wallet balance
  getBalance @6 (context :Common.Context) -> (result :Common.Result(Balance));

  # Save wallet state
  save @7 (context :Common.Context) -> (result :Common.Result(Bool));

  # Load wallet state
  load @8 (context :Common.Context) -> (result :Common.Result(Bool));
}