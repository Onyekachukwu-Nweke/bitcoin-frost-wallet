#![allow(warnings)]
// Include the generated Cap'n Proto code
pub mod common_capnp {
    include!(concat!(env!("OUT_DIR"), "/common_capnp.rs"));
}

pub mod dkg_capnp {
    include!(concat!(env!("OUT_DIR"), "/dkg_capnp.rs"));
}

pub mod frost_capnp {
    include!(concat!(env!("OUT_DIR"), "/frost_capnp.rs"));
}

pub mod wallet_capnp {
    include!(concat!(env!("OUT_DIR"), "/wallet_capnp.rs"));
}

// Utility functions for working with Cap'n Proto
use capnp::message::{Builder, HeapAllocator, Reader};
use capnp::serialize::{self, BufferSegments};
use frost_secp256k1::Identifier;

use crate::common::errors::{FrostWalletError, Result};
pub use common_capnp::*;
pub use dkg_capnp::*;
pub use frost_capnp::*;
pub use wallet_capnp::*;

// Convert a rust Identifier to a Cap'n Proto Identifier
pub fn to_capnp_identifier(builder: &mut Builder<HeapAllocator>, id: Identifier) -> identifier::Builder {
    let mut id_builder = builder.init_root::<identifier::Builder>();

    // Get the debug representation
    let debug_str = format!("{:?}", id);

    println!("Debug representation: {}", debug_str);

    // Extract the hex string without the quotes
    let hex_str = debug_str
        .replace("Identifier(\"", "")
        .replace("\")", "");

    println!("Identifier: {}", hex_str);

    // For a u16 identifier, we need only the last 4 characters of the hex string
    let suffix = if hex_str.len() > 4 {
        &hex_str[hex_str.len() - 4..]
    } else {
        &hex_str
    };

    println!("Hex suffix: {}", suffix);

    // Parse as hexadecimal
    let id_value = match u16::from_str_radix(suffix, 16) {
        Ok(value) => {
            println!("Parsed value: {}", value);
            value
        },
        Err(e) => {
            println!("Error parsing hex: {}", e);
            0
        }
    };

    id_builder.set_value(id_value);
    id_builder
}

// Convert a Cap'n Proto Identifier to a rust Identifier
pub fn from_capnp_identifier(reader: &Reader<BufferSegments<&[u8]>>) -> Result<Identifier> {
    let id_reader = reader.get_root::<identifier::Reader>()
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize identifier: {}", e)))?;

    let id_value = id_reader.get_value();
    Identifier::try_from(id_value)
        .map_err(|e| FrostWalletError::SerializationError(format!("Invalid identifier value: {}", e)))
}

// Create a new Cap'n Proto message builder
pub fn new_message() -> Builder<HeapAllocator> {
    Builder::new_default()
}

// Serialize a Cap'n Proto message to bytes
pub fn serialize_message(builder: &Builder<HeapAllocator>) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    serialize::write_message(&mut buffer, builder)
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize message: {}", e)))?;
    Ok(buffer)
}

// Deserialize bytes to a Cap'n Proto message
pub fn deserialize_message(data: &mut [u8]) -> Result<Reader<BufferSegments<&[u8]>>> {
    let reader = serialize::read_message_from_flat_slice(&mut &*data, Default::default())
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize message: {}", e)))?;
    Ok(reader)
}

#[test]
fn test_identifier_conversion() {
    let original_id = Identifier::try_from(42u16).unwrap();
    let mut builder = new_message();
    let id_builder = to_capnp_identifier(&mut builder, original_id);
    assert_eq!(id_builder.get_value(), 42);
}

#[test]
fn test_message_serialization_deserialization() {
    // Create a new message
    let mut builder = new_message();

    // Initialize a root structure (using ThresholdConfig as an example)
    let mut config_builder = builder.init_root::<threshold_config::Builder>();
    config_builder.set_threshold(3);
    config_builder.set_total_participants(5);

    // Serialize the message
    let mut serialized = serialize_message(&builder).expect("Failed to serialize message");

    // Deserialize the message
    let reader = deserialize_message(&mut serialized).expect("Failed to deserialize message");

    // Read the values from the deserialized message
    let config_reader = reader.get_root::<threshold_config::Reader>().expect("Failed to get root");

    // Verify values match
    assert_eq!(config_reader.get_threshold(), 3);
    assert_eq!(config_reader.get_total_participants(), 5);
}

#[test]
fn test_process_type_conversion() {
    // Create a new message
    let mut builder = new_message();

    // Initialize a root structure with a process ID
    let mut process_id_builder = builder.init_root::<process_id::Builder>();

    // Set the process type to coordinator
    process_id_builder.set_type(ProcessType::Coordinator);
    process_id_builder.set_id(42);

    // Serialize the message
    let mut serialized = serialize_message(&builder).expect("Failed to serialize process_id");

    // Deserialize the message
    let reader = deserialize_message(&mut serialized).expect("Failed to deserialize process_id");

    // Read the deserialized data
    let process_id_reader = reader.get_root::<process_id::Reader>().expect("Failed to get root");

    // Verify process type and ID
    assert_eq!(process_id_reader.get_type(), Ok(ProcessType::Coordinator));
    assert_eq!(process_id_reader.get_id(), 42);

    // Now test with the participant type
    let mut builder = new_message();
    let mut process_id_builder = builder.init_root::<process_id::Builder>();
    process_id_builder.set_type(ProcessType::Participant);
    process_id_builder.set_id(123);

    let mut serialized = serialize_message(&builder).expect("Failed to serialize second process_id");
    let reader = deserialize_message(&mut serialized).expect("Failed to deserialize second process_id");
    let process_id_reader = reader.get_root::<process_id::Reader>().expect("Failed to get second root");

    assert_eq!(process_id_reader.get_type(), Ok(ProcessType::Participant));
    assert_eq!(process_id_reader.get_id(), 123);
}