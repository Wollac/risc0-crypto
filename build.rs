use cargo_metadata::MetadataCommand;
use std::{env, fs, path::PathBuf};

fn main() {
    // 1. Grab the OUT_DIR environment variable provided by Cargo
    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR is not set");
    let out_dir_path = PathBuf::from(out_dir);

    // 2. Execute `cargo metadata` to get the project tree
    let metadata = MetadataCommand::new().exec().expect("Failed to execute cargo metadata");

    // 3. Locate 'risc0-bigint2' in the dependency graph
    let target_crate = "risc0-bigint2";
    let pkg = metadata
        .packages
        .iter()
        .find(|p| p.name == target_crate)
        .unwrap_or_else(|| panic!("Could not find '{target_crate}' in dependency tree"));

    // 4. Get the root directory of the dependency (parent of its Cargo.toml)
    let dep_dir = pkg.manifest_path.parent().expect("Failed to get parent dir");

    // 5. Define the exact paths to the blobs you want to copy.
    let blobs = vec![
        "src/ec/ec_add_256.blob",
        "src/ec/ec_double_256.blob",
        "src/ec/ec_add_384.blob",
        "src/ec/ec_double_384.blob",
    ];

    // 6. Loop through and copy them to your OUT_DIR
    for blob in blobs {
        let src_path = dep_dir.join(blob);

        // Extract just the filename so we can drop it directly into OUT_DIR
        let file_name = src_path.file_name().expect("Blob path must have a filename");
        let dest_path = out_dir_path.join(file_name);

        fs::copy(&src_path, &dest_path).unwrap_or_else(|e| {
            panic!("Failed to copy blob from {} to {}: {}", src_path, dest_path.display(), e)
        });

        // Tell Cargo to re-run the build script if these specific source files change.
        // (Helpful if you are using a local path dependency for risc0-bigint2)
        println!("cargo:rerun-if-changed={}", src_path.as_str());
    }

    // Always re-run if the build script itself is modified
    println!("cargo:rerun-if-changed=build.rs");
}
