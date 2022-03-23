use std::process::Command;

use anyhow::Result;
use capsule::config::RuntimeConfig;
use capsule::Runtime;

use crate::Env;

pub fn build_runtime(config: RuntimeConfig, env: Env) -> Result<Runtime> {
    let runtime = Runtime::build(config);
    if env == Env::Nuc {
        // connect physical NICs to TAP interfaces
        Command::new("./init_tuntap.sh").output()?;
    }
    // set up control TAP interface
    Command::new("./init_sidecar.sh").output()?;
    runtime
}
