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

use capnp::message::{Builder, Reader};
use capnp::serialize;
use frost_secp256k1::Identifier;
use std::io::Cursor;

use crate::common::errors::{FrostWalletError, Result};
use common_capnp::identifier;

// Convert a rust Identifier to a Cap'n Proto Identifier
pub fn to_capnp_identifier(builder: &mut Builder, id: Identifier) -> identifier::Builder {
    let mut id_builder = builder.init_root::<identifier::Builder>();
    id_builder.set_value(id.value() as u16);
    id_builder
}

// Convert a Cap'n Proto Identifier to a rust Identifier
pub fn from_capnp_identifier(reader: &Reader<Cursor<Vec<u8>>>) -> Result<Identifier> {
    let id_reader = reader.get_root::<identifier::Reader>()
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize identifier: {}", e)))?;

    let id_value = id_reader.get_value();
    Identifier::try_from(id_value)
        .map_err(|e| FrostWalletError::SerializationError(format!("Invalid identifier value: {}", e)))
}

// Serialize a Cap'n Proto message to bytes
pub fn serialize_message<T>(builder: &Builder<T>) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    serialize::write_message(&mut buffer, builder)
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize message: {}", e)))?;
    Ok(buffer)
}

// Deserialize bytes to a Cap'n Proto message
pub fn deserialize_message(data: &[u8]) -> Result<Reader<Cursor<Vec<u8>>>> {
    let cursor = Cursor::new(data.to_vec());
    let reader = serialize::read_message(cursor, Default::default())
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize message: {}", e)))?;
    Ok(reader)
}