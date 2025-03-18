#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::time::Duration;
    use frost_secp256k1::{Identifier, VerifyingKey};
    use frost_secp256k1::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
    use rand_core::OsRng;
    use tokio::time::sleep;
    use crate::common::errors::FrostWalletError;
    use crate::common::types::{Participant, ThresholdConfig};
    use crate::frost::coordinator::{CoordinatorController, FrostCoordinator};
    use crate::frost::participant::{FrostParticipant, SigningParticipant};

    fn generate_test_key_packages(threshold: u16, total: u16) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
        let (secret_shares, pub_key_package) = frost_secp256k1::keys::generate_with_dealer(
            total,
            threshold,
            IdentifierList::Default,
            &mut OsRng,
        ).expect("Failed to generate key packages");

        let key_packages: BTreeMap<_, _> = secret_shares.into_iter()
            .map(|(id, ss)| {
                let key_package = KeyPackage::try_from(ss)
                    .map_err(|e| FrostWalletError::FrostError("Failed to convert to KeyPackage".to_string()))
                    .unwrap();
                (id, key_package)
            })
            .collect();

        (key_packages, pub_key_package)
    }

    // Helper function to create a set of frost participants
    fn create_frost_participants(
        key_packages: &BTreeMap<Identifier, KeyPackage>,
        pub_key_package: &PublicKeyPackage
    ) -> BTreeMap<Identifier, FrostParticipant> {
        key_packages.iter()
            .map(|(id, key_package)| {
                (*id, FrostParticipant::new(*id, key_package.clone(), pub_key_package.clone()))
            })
            .collect()
    }

    #[test]
    fn test_coordinator_based_frost_signing() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create participants with their respective key packages
        let participants = create_frost_participants(&key_packages, &pub_key_package);

        // Create a message to sign
        let message = b"Test message for coordinator-based signing";

        // Define the signers for this session
        let signer_ids: Vec<Identifier> = participants.keys().copied().take(2).collect();

        // Create a coordinator (doesn't have signing capability)
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);
        coordinator.set_public_key_package(pub_key_package.clone());

        // Register participants with the coordinator
        for &id in &signer_ids {
            coordinator.add_participant(Participant::new(id));
        }

        // 1. Coordinator initiates signing session
        coordinator.start_signing(message.to_vec()).unwrap();

        // 2. Participants generate and send commitments to coordinator (Round 1)
        let mut nonces_map = HashMap::new();

        for &id in &signer_ids {
            let participant = participants.get(&id).unwrap();
            let (commitment, nonces) = participant.generate_commitment().unwrap();

            // Send commitment to coordinator (simulated)
            coordinator.add_commitment(id, commitment).unwrap();

            // Participant stores their nonces for later use
            nonces_map.insert(id, nonces);
        }

        // 3. Coordinator creates signing package and distributes to participants
        assert!(coordinator.has_all_commitments(&signer_ids));
        let signing_package = coordinator.create_signing_package(&signer_ids).unwrap();

        // 4. Participants generate signature shares and send to coordinator (Round 2)
        let mut signature_shares = BTreeMap::new();

        for &id in &signer_ids {
            let participant = participants.get(&id).unwrap();
            let nonces = nonces_map.get(&id).unwrap();

            // Generate signature share
            let signature_share = participant
                .generate_signature_share(nonces, &signing_package)
                .unwrap();

            // Send signature share to coordinator (simulated)
            signature_shares.insert(id, signature_share);
        }

        // 5. Coordinator aggregates signature shares to form final signature
        let signature = coordinator
            .aggregate_signature_shares(&signing_package, &signature_shares)
            .unwrap();

        // 6. Coordinator verifies the signature
        let valid = coordinator.verify_signature(message, &signature).unwrap();
        assert!(valid, "Signature verification failed");

        // 7. Reset for next signing session
        coordinator.clear_signing_session();
    }

    #[test]
    fn test_complete_signing_flow() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create participants with their respective key packages
        let participants = create_frost_participants(&key_packages, &pub_key_package);

        // Create a message to sign
        let message = b"Test message for complete signing flow";

        // Define signers for this session
        let signer_ids: Vec<Identifier> = participants.keys().copied().take(2).collect();

        // Create coordinator
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);
        coordinator.set_public_key_package(pub_key_package.clone());

        // 1. Coordinator setup - register all participants
        for &id in &signer_ids {
            coordinator.add_participant(Participant::new(id));
        }

        // 2. Initialize signing session
        coordinator.start_signing(message.to_vec()).unwrap();

        // 3. Participants generate commitments
        let mut nonces_map = HashMap::new();
        for &id in &signer_ids {
            let participant = participants.get(&id).unwrap();
            let (commitment, nonces) = participant.generate_commitment().unwrap();
            coordinator.add_commitment(id, commitment).unwrap();
            nonces_map.insert(id, nonces);
        }

        // 4. Coordinator creates and distributes signing package
        let signing_package = coordinator.create_signing_package(&signer_ids).unwrap();

        // 5. Participants generate signature shares
        let mut signature_shares = BTreeMap::new();
        for &id in &signer_ids {
            let participant = participants.get(&id).unwrap();
            let nonces = nonces_map.get(&id).unwrap();
            let signature_share = participant.generate_signature_share(nonces, &signing_package).unwrap();
            signature_shares.insert(id, signature_share);
        }

        // 6. Coordinator aggregates shares into final signature
        let signature = coordinator.aggregate_signature_shares(&signing_package, &signature_shares).unwrap();

        // 7. Verify signature
        let verification_result = VerifyingKey::verify(
            pub_key_package.verifying_key(),
            message,
            &signature,
        );

        assert!(verification_result.is_ok(), "Signature verification failed");
    }

    #[test]
    fn test_not_enough_signers() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create participants
        let participants = create_frost_participants(&key_packages, &pub_key_package);

        // Create a message to sign
        let message = b"Test message for threshold validation";

        // Try to sign with only one signer (below threshold)
        let signers: Vec<Identifier> = participants.keys().copied().take(1).collect();

        // Create a coordinator with threshold 2
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);

        // Register just one participant
        for &id in &signers {
            coordinator.add_participant(Participant::new(id));
        }

        // Attempt to start signing session
        let result = coordinator.start_signing(message.to_vec());
        assert!(result.is_err());

        if let Err(FrostWalletError::NotEnoughSigners { required, provided }) = result {
            assert_eq!(required, 2);
            assert_eq!(provided, 1);
        } else {
            panic!("Expected NotEnoughSigners error");
        }
    }

    #[tokio::test]
    async fn test_signing_coordinator_architecture() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);
        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let participant1_id = Identifier::try_from(2u16).unwrap();
        let participant2_id = Identifier::try_from(3u16).unwrap();
        let coordinator_port = 36000;

        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = CoordinatorController::new(coordinator_id, config.clone(), coordinator_port);
        coordinator.set_public_key_package(pub_key_package.clone()).unwrap();

        coordinator.start_server().await.unwrap();
        let coordinator_addr = coordinator.get_server_addr().unwrap();
        println!("Coordinator server started at {:?}", coordinator_addr);

        let mut participant1 = SigningParticipant::new(
            participant1_id,
            key_packages.get(&participant1_id).unwrap().clone(),
            pub_key_package.clone(),
        );
        participant1.connect_to_coordinator(coordinator_id, coordinator_addr).await.unwrap();
        println!("Participant 1 connected to coordinator");

        let mut participant2 = SigningParticipant::new(
            participant2_id,
            key_packages.get(&participant2_id).unwrap().clone(),
            pub_key_package.clone(),
        );
        participant2.connect_to_coordinator(coordinator_id, coordinator_addr).await.unwrap();
        println!("Participant 2 connected to coordinator");

        sleep(Duration::from_millis(200)).await;

        coordinator.connect_to_participant(participant1_id, coordinator_addr).await.unwrap();
        coordinator.connect_to_participant(participant2_id, coordinator_addr).await.unwrap();

        sleep(Duration::from_millis(500)).await;
        println!("All connections established");

        let p1_handle = tokio::spawn(async move {
            participant1.run().await
        });
        let p2_handle = tokio::spawn(async move {
            participant2.run().await
        });

        sleep(Duration::from_millis(500)).await;
        println!("Participants started, beginning signing process");

        let message = b"Test message with coordinator architecture".to_vec();
        let signers = vec![participant1_id, participant2_id];

        let signature = coordinator.coordinate_signing(message.clone(), signers).await.unwrap();
        println!("Signing completed, verifying signature");

        let verification_result = VerifyingKey::verify(
            pub_key_package.verifying_key(),
            &message,
            &signature,
        );
        assert!(verification_result.is_ok(), "Signature verification failed");

        println!("Signature verified successfully!");
        p1_handle.abort();
        p2_handle.abort();
        coordinator.cleanup().await.unwrap();
    }
}