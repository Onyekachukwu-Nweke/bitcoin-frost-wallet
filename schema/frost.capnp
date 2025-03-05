@0xc71d572b4db67e52;

using Common = import "common.capnp";
using Dkg = import "dkg.capnp";

struct SigningCommitment {
  participantId @0 :Common.Identifier;
  commitment @1 :Data;
}

struct SignatureShare {
  participantId @0 :Common.Identifier;
  shareData @1 :Data;
}

struct SigningPackage {
  message @0 :Data;
  commitments @1 :List(SigningCommitment);
}

struct Signature {
  data @0 :Data;
}

struct SigningRequest {
  messageHash @0 :Data;
  signers @1 :List(Common.Identifier);
}

interface FrostCoordinator {
  # Initialize with a threshold config and public key package
  initialize @0 (context :Common.Context, config :Common.ThresholdConfig, pubKeyPackage :Dkg.PublicKeyPackage) -> (result :Common.Result(Bool));

  # Start a signing session for a message
  startSigning @1 (context :Common.Context, message :Data) -> (result :Common.Result(Bool));

  # Add a participant's commitment to the signing session
  addCommitment @2 (context :Common.Context, commitment :SigningCommitment) -> (result :Common.Result(Bool));

  # Create a signing package from collected commitments
  createSigningPackage @3 (context :Common.Context) -> (result :Common.Result(SigningPackage));

  # Add a signature share to the signing session
  addSignatureShare @4 (context :Common.Context, share :SignatureShare) -> (result :Common.Result(Bool));

  # Aggregate signature shares into a complete signature
  aggregateSignatures @5 (context :Common.Context) -> (result :Common.Result(Signature));

  # Verify a signature against a message
  verifySignature @6 (context :Common.Context, message :Data, signature :Signature) -> (result :Common.Result(Bool));
}

interface FrostParticipant {
  # Initialize with participant ID and key package
  initialize @0 (context :Common.Context, participantId :Common.Identifier, keyPackage :Dkg.KeyPackage) -> (result :Common.Result(Bool));

  # Generate a signing commitment for a message
  generateCommitment @1 (context :Common.Context) -> (result :Common.Result(SigningCommitment));

  # Generate a signature share using the signing package
  generateSignatureShare @2 (context :Common.Context, signingPackage :SigningPackage) -> (result :Common.Result(SignatureShare));
}