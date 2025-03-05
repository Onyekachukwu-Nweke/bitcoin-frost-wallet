@0xf92a5b7dbcf4ca3e;

using Common = import "common.capnp";

enum DkgRoundState {
  round1 @0;
  round2 @1;
  round3 @2;
  complete @3;
  failed @4;
}

struct Round1Package {
  participantId @0 :Common.Identifier;
  commitment @1 :Data;
}

struct Round2Package {
  fromId @0 :Common.Identifier;
  toId @1 :Common.Identifier;
  keyShare @2 :Data;
}

struct KeyPackage {
  participantId @0 :Common.Identifier;
  keyData @1 :Data;
}

struct PublicKeyPackage {
  data @0 :Data;
}

interface DkgCoordinator {
  # Initialize DKG with the given config
  initialize @0 (context :Common.Context, config :Common.ThresholdConfig) -> (result :Common.Result(Bool));

  # Add a participant to the DKG session
  addParticipant @1 (context :Common.Context, participantId :Common.Identifier) -> (result :Common.Result(Bool));

  # Start the DKG process
  start @2 (context :Common.Context) -> (result :Common.Result(Bool));

  # Process a Round 1 package
  processRound1Package @3 (context :Common.Context, package :Round1Package) -> (result :Common.Result(Bool));

  # Process a Round 2 package
  processRound2Package @4 (context :Common.Context, package :Round2Package) -> (result :Common.Result(Bool));

  # Finalize DKG for a participant
  finalize @5 (context :Common.Context, participantId :Common.Identifier) -> (result :Common.Result(KeyPackage));

  # Get the current round state
  getRoundState @6 (context :Common.Context) -> (state :DkgRoundState);

  # Get the public key package
  getPublicKeyPackage @7 (context :Common.Context) -> (result :Common.Result(PublicKeyPackage));
}

interface DkgParticipant {
  # Initialize the participant with an ID
  initialize @0 (context :Common.Context, participantId :Common.Identifier) -> (result :Common.Result(Bool));

  # Generate a Round 1 package
  generateRound1Package @1 (context :Common.Context) -> (result :Common.Result(Round1Package));

  # Generate a Round 2 package for a recipient
  generateRound2Package @2 (context :Common.Context, recipientId :Common.Identifier) -> (result :Common.Result(Round2Package));

  # Process a finalized key package
  processKeyPackage @3 (context :Common.Context, keyPackage :KeyPackage) -> (result :Common.Result(Bool));
}