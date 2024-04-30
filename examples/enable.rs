// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate error_chain;

use pfctl::PfCtl;

error_chain! {}
quick_main!(run);

fn run() -> Result<()> {
    // Create a handle to the firewall. This opens the file /dev/pf and requires root.
    let mut pf = PfCtl::new().chain_err(|| "Unable to connect to PF")?;

    // Try to enable the firewall. Equivalent to the CLI command "pfctl -e".
    match pf.enable() {
        Ok(_) => println!("Enabled PF"),
        Err(pfctl::Error {
            source: pfctl::ErrorSource::StateAlreadyActive(_),
            ..
        }) => (),
        err => err.chain_err(|| "Unable to enable PF")?,
    }
    Ok(())
}
