use secp256k1::{Scalar, PublicKey, SecretKey};
use std::collections::HashMap;
use crate::error::Error;

pub type PartyId = u16;
pub type Threshold = u16;
pub type ShareId = u16;

#[derive(Debug, Clone)]
pub struct Party {
    pub id: PartyId,
    pub share: SecretKey,
    pub public_share: PublicKey,
    pub commitments: Vec<(Scalar, PublicKey)>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub threshold: Threshold,
    pub total_parties: u16,
}

impl Config {
    pub fn new(threshold: Threshold, total_parties: u16) -> Result<Self, Error> {
        if threshold == 0 || threshold > total_parties {
            return Err(Error::InvalidThreshold);
        }
        Ok(Self { threshold, total_parties })
    }
}