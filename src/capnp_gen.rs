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
// Re-export other modules as needed
// pub use dkg_capnp::*;
// pub use frost_capnp::*;
// pub use wallet_capnp::*;

// Convert a rust Identifier to a Cap'n Proto Identifier
pub fn to_capnp_identifier(builder: &mut Builder<HeapAllocator>, id: Identifier) -> identifier::Builder {
    let mut id_builder = builder.init_root::<identifier::Builder>();
    // Use the to_string() method and parse it, since frost-secp256k1 doesn't expose a direct way to get the raw value
    let id_str = id.to_string();
    let id_value = id_str.parse::<u16>().unwrap_or(0);
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