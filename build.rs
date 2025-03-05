fn main() {
    // This tells Cargo to rerun this script if any of the schema files change
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed=schema/");

    // Generate Rust code from Cap'n Proto schema files
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .output_path(&out_dir)
        .file("schema/common.capnp")
        .file("schema/frost.capnp")
        .file("schema/dkg.capnp")
        .file("schema/wallet.capnp")
        .run()
        .expect("Failed to compile Cap'n Proto schema files");
}