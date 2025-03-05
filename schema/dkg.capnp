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

# Result wrapper structs
struct BoolResult {
  success @0 :Bool;
  error @1 :Common.Error;
  value @2 :Bool;
}

struct KeyPackageResult {
  success @0 :Bool;
  error @1 :Common.Error;
  value @2 :KeyPackage;
}

struct PublicKeyPackageResult {
  success @0 :Bool;
  error @1 :Common.Error;
  value @2 :PublicKeyPackage;
}

struct Round1PackageResult {
  success @0 :Bool;
  error @1 :Common.Error;
  value @2 :Round1Package;
}

struct Round2PackageResult {
  success @0 :Bool;
  error @1 :Common.Error;
  value @2 :Round2Package;
}

interface DkgCoordinator {
  # Initialize DKG with the given config
  initialize @0 (context :Common.Context, config :Common.ThresholdConfig) -> (result :BoolResult);

  # Add a participant to the DKG session
  addParticipant @1 (context :Common.Context, participantId :Common.Identifier) -> (result :BoolResult);

  # Start the DKG process
  start @2 (context :Common.Context) -> (result :BoolResult);

  # Process a Round 1 package
  processRound1Package @3 (context :Common.Context, package :Round1Package) -> (result :BoolResult);

  # Process a Round 2 package
  processRound2Package @4 (context :Common.Context, package :Round2Package) -> (result :BoolResult);

  # Finalize DKG for a participant
  finalize @5 (context :Common.Context, participantId :Common.Identifier) -> (result :KeyPackageResult);

  # Get the current round state
  getRoundState @6 (context :Common.Context) -> (state :DkgRoundState);

  # Get the public key package
  getPublicKeyPackage @7 (context :Common.Context) -> (result :PublicKeyPackageResult);
}

interface DkgParticipant {
  # Initialize the participant with an ID
  initialize @0 (context :Common.Context, participantId :Common.Identifier) -> (result :BoolResult);

  # Generate a Round 1 package
  generateRound1Package @1 (context :Common.Context) -> (result :Round1PackageResult);

  # Generate a Round 2 package for a recipient
  generateRound2Package @2 (context :Common.Context, recipientId :Common.Identifier) -> (result :Round2PackageResult);

  # Process a finalized key package
  processKeyPackage @3 (context :Common.Context, keyPackage :KeyPackage) -> (result :BoolResult);
}