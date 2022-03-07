use std::process::Command;

use anyhow::Result;
use capsule::config::RuntimeConfig;
use capsule::Runtime;

use crate::Env;

pub fn build_runtime(config: RuntimeConfig, env: Env) -> Result<Runtime> {
    let runtime = Runtime::build(config);
    if env == Env::Nuc {
        Command::new("./init_tuntap.sh").output()?;
    }
    runtime
}
