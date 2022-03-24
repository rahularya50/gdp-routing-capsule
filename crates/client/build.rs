use std::env;

use anyhow::Result;

fn main() -> Result<()> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::Cxx)
        .generate()?
        .write_to_file("gdp_client.hpp");

    Ok(())
}
