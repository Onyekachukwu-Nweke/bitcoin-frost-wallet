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

struct Result(Type) {
  success @0 :Bool;
  value @1 :Type;
  error @2 :Error;
}@0xd28c9bd42c5ca179;

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

 struct Result(Type) {
   success @0 :Bool;
   value @1 :Type;
   error @2 :Error;
 }