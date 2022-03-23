use std::env;

use anyhow::Result;

fn main() -> Result<()> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;

    cbindgen::Builder::new()
        .with_crate(crate_dir.clone())
        .with_language(cbindgen::Language::Cxx)
        .generate()?
        .write_to_file("bindings.hpp");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::Cython)
        .generate()?
        .write_to_file("bindings.pyx");

    Ok(())
}
