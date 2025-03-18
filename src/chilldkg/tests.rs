#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use frost_secp256k1::Identifier;
    use crate::chilldkg::coordinator::{DkgCoordinator, DkgProcessController};
    use crate::chilldkg::participant::{DkgParticipant, DkgParticipantProcess};
    use crate::common::types::{DkgRoundState, Participant, ThresholdConfig};

    #[test]
    fn test_dkg_with_separate_coordinator_and_participants() {
        // Create a coordinator and participants
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = DkgCoordinator::new(config.clone());

        // Create participants
        let mut participants = BTreeMap::new();
        for i in 1..=3 {
            let id = Identifier::try_from(i as u16).unwrap();
            let participant = Participant::new(id);
            coordinator.add_participant(participant).unwrap();

            participants.insert(id, DkgParticipant::new(id, config.clone()));
        }

        // Start DKG
        coordinator.start().unwrap();
        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round1));

        // Round 1: Generate and share commitments
        let mut round1_packages = BTreeMap::new();
        for (&id, participant) in &mut participants {
            let package = participant.generate_round1().unwrap();
            round1_packages.insert(id, package.clone());
            coordinator.process_round1_package(id, package).unwrap();
        }

        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round2));

        // Round 2: Generate and exchange encrypted key shares
        for (&sender_id, participant) in &mut participants {
            let packages = participant.generate_round2(&round1_packages).unwrap();

            // Send each package to the coordinator
            for (recipient_id, package) in &packages {
                coordinator.process_round2_package(sender_id, *recipient_id, package.clone()).unwrap();
            }
        }

        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round3));

        // Round 3: Finalize locally (no coordinator involvement)
        let mut pub_key_packages = Vec::new();

        for (&id, participant) in &mut participants {
            // Get round 2 packages intended for this participant
            let round2_packages_for_me = coordinator.get_round2_packages_for_recipient(id).unwrap();

            // Finalize
            let (_key_package, public_key_package) = participant.finalize(
                &round1_packages,
                &round2_packages_for_me
            ).unwrap();

            pub_key_packages.push(public_key_package);
        }

        // Verify all participants have the same public key
        let first_pub_key = pub_key_packages[0].verifying_key();
        for pkg in &pub_key_packages[1..] {
            assert_eq!(first_pub_key, pkg.verifying_key());
        }

        // Note: Coordinator no longer holds or returns a public key package
        // The test now verifies participant consistency only
        log::info!("DKG completed successfully with consistent public keys among participants.");
    }

    #[tokio::test]
    async fn test_dkg_coordinator_and_participants() {
        let port = 35000;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let participant1_id = Identifier::try_from(2u16).unwrap();
        let participant2_id = Identifier::try_from(3u16).unwrap();
        let participant3_id = Identifier::try_from(4u16).unwrap();

        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = DkgProcessController::new(coordinator_id, config.clone(), port);
        coordinator.start_server().await.unwrap();

        let mut participant1 = DkgParticipantProcess::new(participant1_id, config.clone());
        let mut participant2 = DkgParticipantProcess::new(participant2_id, config.clone());
        let mut participant3 = DkgParticipantProcess::new(participant3_id, config.clone());

        coordinator.add_participant(Participant::new(participant1_id)).unwrap();
        coordinator.add_participant(Participant::new(participant2_id)).unwrap();
        coordinator.add_participant(Participant::new(participant3_id)).unwrap();

        participant1.connect_to_coordinator(server_addr).await.unwrap();
        participant2.connect_to_coordinator(server_addr).await.unwrap();
        participant3.connect_to_coordinator(server_addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let participant1_task = tokio::spawn(async move {
            participant1.run_dkg().await.unwrap()
        });

        let participant2_task = tokio::spawn(async move {
            participant2.run_dkg().await.unwrap()
        });

        let participant3_task = tokio::spawn(async move {
            participant3.run_dkg().await.unwrap()
        });

        coordinator.run_dkg().await.unwrap();

        let key_package1 = participant1_task.await.unwrap();
        let key_package2 = participant2_task.await.unwrap();
        let key_package3 = participant3_task.await.unwrap();

        assert_eq!(key_package1.verifying_key(), key_package2.verifying_key());
        assert_eq!(key_package2.verifying_key(), key_package3.verifying_key());

        coordinator.cleanup().await.unwrap();
    }

    #[tokio::test]
    async fn test_dkg_with_different_threshold() {
        // Use different port for each test to avoid conflicts
        let port = 35001;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        // Create a 3-of-5 threshold configuration for this test
        // Note: This means 5 actual participants, not including the coordinator
        let config = ThresholdConfig::new(3, 5);

        // Initialize coordinator (not a participant)
        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let mut coordinator = DkgProcessController::new(coordinator_id, config.clone(), port);
        coordinator.start_server().await.unwrap();

        // Initialize 5 participants (coordinator is NOT counted as a participant)
        let mut participants = Vec::new();
        let mut participant_tasks = Vec::new();

        for i in 2..=6 { // Creating 5 participants with IDs 2-6
            let id = Identifier::try_from(i).unwrap();
            let mut participant = DkgParticipantProcess::new(id, config.clone());

            // Connect to coordinator
            participant.connect_to_coordinator(server_addr).await.unwrap();

            // Add to coordinator's list (for tracking only)
            coordinator.add_participant(Participant::new(id)).unwrap();

            participants.push(participant);
        }

        // Wait for connections to be established
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Start participant processes in separate tasks
        for mut participant in participants {
            let task = tokio::spawn(async move {
                participant.run_dkg().await.unwrap()
            });
            participant_tasks.push(task);
        }

        // Run coordinator (only facilitates communication)
        let pub_key_package = coordinator.run_dkg().await.unwrap();

        // Wait for all participants to complete
        let mut key_packages = Vec::new();
        for task in participant_tasks {
            key_packages.push(task.await.unwrap());
        }

        // Verify all participants derived the same public key
        let first_key = &key_packages[0].verifying_key();
        for key_package in &key_packages {
            assert_eq!(key_package.verifying_key(), *first_key);
        }

        // Clean up
        coordinator.cleanup().await.unwrap();
    }
}