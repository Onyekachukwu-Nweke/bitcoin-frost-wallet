fn main() {
    // This tells Cargo to rerun this script if any of the schema files change
    println!("cargo:rerun-if-changed=schema/");

    // Generate Rust code from Cap'n Proto schema files
    capnpc::CompilerCommand::new()
        .file("schema/common.capnp")
        .file("schema/frost.capnp")
        .file("schema/dkg.capnp")
        .file("schema/wallet.capnp")
        .run()
        .expect("Failed to compile Cap'n Proto schema files");
}