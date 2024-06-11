// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate error_chain;

use pfctl::PfCtl;
use std::env;

error_chain! {}
quick_main!(run);

fn run() -> Result<()> {
    let mut pf = PfCtl::new().chain_err(|| "Unable to connect to PF")?;

    for anchor_name in env::args().skip(1) {
        match pf.flush_rules(&anchor_name, pfctl::RulesetKind::Filter) {
            Ok(_) => println!("Flushed filter rules under anchor {}", anchor_name),
            err => err.chain_err(|| "Unable to flush filter rules")?,
        }
        match pf.flush_rules(&anchor_name, pfctl::RulesetKind::Redirect) {
            Ok(_) => println!("Flushed redirect rules under anchor {}", anchor_name),
            err => err.chain_err(|| "Unable to flush redirect rules")?,
        }
    }
    Ok(())
}
