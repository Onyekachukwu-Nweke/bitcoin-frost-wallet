@0xd28c9bd42c5ca179;

struct Identifier {
  value @0 :UInt16;
}

struct ThresholdConfig {
  threshold @0 :UInt16;
  totalParticipants @1 :UInt16;
}

struct Context {
  timestamp @0 :UInt64;
  processId @1 :UInt32;
}

enum ProcessType {
  coordinator @0;
  participant @1;
}

struct ProcessId {
  type @0 :ProcessType;
  id @1 :UInt16;
}

struct Error {
  code @0 :UInt16;
  message @1 :Text;
}

# Instead of generic Result, we need specific result types for each type
# These are defined in the respective schema files that need them