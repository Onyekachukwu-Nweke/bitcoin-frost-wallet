#![allow(warnings)]
use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{Participant, ThresholdConfig};
use frost_secp256k1::{
    keys::{dkg::{part1, part2, part3, round1, round2}, KeyPackage, PublicKeyPackage},
    Identifier,
};
use rand_core::OsRng;
use std::collections::BTreeMap;

/// State for a ChillDKG round
#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub enum DkgRoundState {
    /// Round 1: Generate and share commitments
    Round1,
    /// Round 2: Generate and exchange encrypted secret shares
    Round2,
    /// Round 3: Verify and finalize
    Round3,
    /// DKG complete
    Complete,
    /// DKG failed
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1::Identifier;

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
}