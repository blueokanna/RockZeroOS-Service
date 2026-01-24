use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_file = PathBuf::from(&crate_dir)
        .join("include")
        .join("rockzero_zkp.h");

    // Create include directory if it doesn't exist
    std::fs::create_dir_all(PathBuf::from(&crate_dir).join("include")).ok();

    // Generate C header file
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_include_guard("ROCKZERO_ZKP_H")
        .with_documentation(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(output_file);
}
