use std::net::SocketAddr;
use frost_secp256k1::{Identifier, Signature, SigningPackage, VerifyingKey};
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1::round2::SignatureShare;
use log::{debug, error, info, warn};
use rand_core::OsRng;
use crate::common::errors::FrostWalletError;
use crate::common::types::{IpcMessage, SigningMessage};
use crate::ipc::IpcClient;

/// FROST Participant - Each signer in the threshold signature scheme
/// Handles cryptographic operations specific to a single participant
pub struct FrostParticipant {
    /// Participant identifier
    id: Identifier,
    /// Key package containing the participant's signing key
    key_package: KeyPackage,
    /// Public key package for verification
    pub_key_package: PublicKeyPackage,
}

impl FrostParticipant {
    /// Create a new FROST participant
    pub fn new(id: Identifier, key_package: KeyPackage, pub_key_package: PublicKeyPackage) -> Self {
        Self {
            id,
            key_package,
            pub_key_package,
        }
    }

    /// Get the participant's ID
    pub fn get_id(&self) -> Identifier {
        self.id
    }

    /// Generate signing commitments (Round 1)
    /// Called when the participant is asked to participate in signing
    pub fn generate_commitment(&self) -> crate::common::errors::Result<(SigningCommitments, SigningNonces)> {
        let signing_share = self.key_package.signing_share();
        let (nonces, commitments) = frost_secp256k1::round1::commit(signing_share, &mut OsRng);
        Ok((commitments, nonces))
    }

    /// Generate a signature share (Round 2)
    /// Called after receiving the signing package from the coordinator
    pub fn generate_signature_share(
        &self,
        nonces: &SigningNonces,
        signing_package: &SigningPackage,
    ) -> crate::common::errors::Result<SignatureShare> {
        let signature_share = frost_secp256k1::round2::sign(
            signing_package,
            nonces,
            &self.key_package,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

        Ok(signature_share)
    }

    /// Verify a signature (for participants to verify the final result)
    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> crate::common::errors::Result<bool> {
        let result = VerifyingKey::verify(
            self.pub_key_package.verifying_key(),
            message,
            signature,
        ).map(|()| true)
            .unwrap_or(false);

        Ok(result)
    }
}

pub struct SigningParticipant {
    local_id: Identifier,
    frost_participant: FrostParticipant,
    coordinator_client: Option<IpcClient>,
    current_message: Option<Vec<u8>>,
    current_signers: Vec<Identifier>,
    current_nonces: Option<SigningNonces>,
}

impl SigningParticipant {
    pub fn new(local_id: Identifier, key_package: KeyPackage, pub_key_package: PublicKeyPackage) -> Self {
        Self {
            local_id,
            frost_participant: FrostParticipant::new(local_id, key_package, pub_key_package),
            coordinator_client: None,
            current_message: None,
            current_signers: Vec::new(),
            current_nonces: None,
        }
    }

    pub async fn connect_to_coordinator(&mut self, coordinator_id: Identifier, addr: SocketAddr) -> crate::common::errors::Result<()> {
        let mut client = IpcClient::new(self.local_id, coordinator_id);
        client.connect(addr).await?;
        self.coordinator_client = Some(client);
        self.coordinator_client.as_ref().unwrap()
            .send(IpcMessage::Handshake(self.local_id)).await?;
        Ok(())
    }

    pub async fn run(&mut self) -> crate::common::errors::Result<()> {
        if self.coordinator_client.is_none() {
            return Err(FrostWalletError::InvalidState("Not connected to coordinator".to_string()));
        }

        info!("Participant {:?} starting", self.local_id);

        loop {
            let message = {
                let client = self.coordinator_client.as_mut().unwrap();
                match client.receive().await {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Error receiving message: {:?}", e);
                        return Err(e);
                    }
                }
            };

            match message {
                IpcMessage::Signing(SigningMessage::Start { message, signers }) => {
                    info!("Received signing request for {} signers", signers.len());
                    debug!("Signers: {:?}", signers);

                    if !signers.contains(&self.local_id) {
                        debug!("I'm not a signer in this session, ignoring");
                        continue;
                    }

                    self.current_message = Some(message);
                    self.current_signers = signers;

                    debug!("Generating commitment");
                    let (commitment, nonces) = self.frost_participant.generate_commitment()?;
                    self.current_nonces = Some(nonces);

                    let serialized_commitment = bincode::serialize(&commitment)?;
                    debug!("Sending commitment to coordinator");
                    let client = self.coordinator_client.as_mut().unwrap();
                    client.send(IpcMessage::Signing(SigningMessage::Round1 {
                        id: self.local_id,
                        commitment: serialized_commitment,
                    })).await?;
                    debug!("Commitment sent successfully");
                },

                IpcMessage::Signing(SigningMessage::SigningPackage { package }) => {
                    info!("Received signing package from coordinator");
                    let signing_package: SigningPackage = bincode::deserialize(&package)?;

                    let nonces = self.current_nonces.as_ref()
                        .ok_or_else(|| FrostWalletError::InvalidState("No signing nonces available".to_string()))?;

                    debug!("Generating signature share");
                    let signature_share = self.frost_participant.generate_signature_share(nonces, &signing_package)?;

                    let serialized_share = bincode::serialize(&signature_share)?;
                    debug!("Sending signature share to coordinator");
                    let client = self.coordinator_client.as_mut().unwrap();
                    client.send(IpcMessage::Signing(SigningMessage::Round2 {
                        id: self.local_id,
                        signature_share: serialized_share,
                    })).await?;
                    debug!("Signature share sent successfully");

                    self.reset_signing_state();
                },

                IpcMessage::Signing(SigningMessage::FinalSignature { signature }) => {
                    info!("Received final signature from coordinator");
                },

                IpcMessage::Handshake(id) => {
                    debug!("Received handshake from {:?}", id);
                },

                _ => {
                    warn!("Unexpected message type: {:?}", message);
                }
            }
        }
    }

    fn reset_signing_state(&mut self) {
        self.current_message = None;
        self.current_signers.clear();
        self.current_nonces = None;
    }
}

impl Drop for SigningParticipant {
    fn drop(&mut self) {
        self.reset_signing_state();
    }
}