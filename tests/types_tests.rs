#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin_frost_wallet::error::Error;
    use bitcoin_frost_wallet::types::Config;

    #[test]
    fn test_config_validation() {
        // Valid config
        assert!(Config::new(2, 3).is_ok());

        // Invalid: threshold = 0
        assert!(matches!(
            Config::new(0, 3),
            Err(Error::InvalidThreshold)
        ));

        // Invalid: threshold > total
        assert!(matches!(
            Config::new(4, 3),
            Err(Error::InvalidThreshold)
        ));
    }
}