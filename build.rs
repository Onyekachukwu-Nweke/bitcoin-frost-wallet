use std::fs;

fn main() {
    // This tells Cargo to rerun this script if any of the schema files change
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:warning=Output directory: {}", out_dir);

    println!("cargo:rerun-if-changed=schema/");

    // Generate Rust code from Cap'n Proto schema files
    capnpc::CompilerCommand::new()
        .file("schema/common.capnp")
        .file("schema/frost.capnp")
        .file("schema/dkg.capnp")
        .file("schema/wallet.capnp")
        .run()
        .expect("Failed to compile Cap'n Proto schema files");

    fix_import_paths(&out_dir);
}

fn fix_import_paths(out_dir: &str) {
    let files = [
        "common_capnp.rs",
        "frost_capnp.rs",
        "dkg_capnp.rs",
        "wallet_capnp.rs",
    ];

    for file in files.iter() {
        let file_path = format!("{}/{}", out_dir, file);
        if let Ok(content) = fs::read_to_string(&file_path) {
            // Replace crate::common_capnp with crate::capnp_gen::common_capnp
            let fixed_content = content.replace(
                "crate::common_capnp",
                "crate::capnp_gen::common_capnp"
            );

            // Replace other possible incorrect imports
            let fixed_content = fixed_content.replace(
                "crate::frost_capnp",
                "crate::capnp_gen::frost_capnp"
            );

            let fixed_content = fixed_content.replace(
                "crate::dkg_capnp",
                "crate::capnp_gen::dkg_capnp"
            );

            let fixed_content = fixed_content.replace(
                "crate::wallet_capnp",
                "crate::capnp_gen::wallet_capnp"
            );

            // Write the fixed content back to the file
            fs::write(file_path, fixed_content).expect("Failed to write fixed file");
        }
    }
}