// risc0-bigint2 exposes raw modular arithmetic functions (modadd, modsub, modmul, modinv) but
// not the EC circuit blobs directly - its EC API wraps them in higher-level functions that don't
// give us enough control over point representation and identity handling.
//
// Work-around: copy the pre-compiled EC circuit blobs from risc0-bigint2's source tree into
// OUT_DIR at build time, then include_bytes! them in curve/ops.rs. This keeps us automatically
// in sync with risc0-bigint2 updates without checking in blobs ourselves.

use cargo_metadata::MetadataCommand;
use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is not set"));
    let metadata = MetadataCommand::new().exec().expect("Failed to execute cargo metadata");

    let target_crate = "risc0-bigint2";
    let pkg = metadata
        .packages
        .iter()
        .find(|p| p.name == target_crate)
        .unwrap_or_else(|| panic!("Could not find '{target_crate}' in dependency tree"));
    let dep_dir = pkg.manifest_path.parent().expect("Failed to get parent dir");

    let blobs = [
        "src/ec/ec_add_256.blob",
        "src/ec/ec_double_256.blob",
        "src/ec/ec_add_384.blob",
        "src/ec/ec_double_384.blob",
    ];

    for blob in blobs {
        let src_path = dep_dir.join(blob);
        let file_name = src_path.file_name().expect("Blob path must have a filename");
        let dest_path = out_dir.join(file_name);

        fs::copy(&src_path, &dest_path).unwrap_or_else(|e| {
            panic!("Failed to copy blob from {} to {}: {}", src_path, dest_path.display(), e)
        });

        // re-run if blob changes (useful with local path dependencies)
        println!("cargo:rerun-if-changed={}", src_path.as_str());
    }

    println!("cargo:rerun-if-changed=build.rs");
}
