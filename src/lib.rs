/// Bitcoin wallet using FROST/ChillDKG with multi-process architecture
pub mod error;
pub mod types;
mod process;

use bitcoin::Network;
use crate::error::{FrostWalletError, Result};
use crate::types::*;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize logging for the library
pub fn init_logging() {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
}

/// Initialize a new wallet with threshold parameters
pub fn init_wallet(threshold: u16, total_participants: u16, network: Network) -> Result<WalletConfig> {
    let config = WalletConfig::new(threshold, total_participants, network);

    if !config.threshold.validate() {
        return Err(FrostWalletError::InvalidThresholdParams(format!(
            "Invalid threshold parameters: threshold={}, total={}",
            threshold, total_participants
        )));
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_init_wallet_valid() {
        let wallet = init_wallet(2, 3, Network::Testnet);
        assert!(wallet.is_ok());

        let config = wallet.unwrap();
        assert_eq!(config.threshold.threshold, 2);
        assert_eq!(config.threshold.total_participants, 3);
        assert_eq!(config.network, Network::Testnet);
    }

    #[test]
    fn test_init_wallet_invalid_threshold() {
        // Threshold cannot be zero
        let wallet = init_wallet(0, 3, Network::Testnet);
        assert!(wallet.is_err());

        // Threshold cannot be greater than total participants
        let wallet = init_wallet(4, 3, Network::Testnet);
        assert!(wallet.is_err());
    }
}