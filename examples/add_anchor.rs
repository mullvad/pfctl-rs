// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate error_chain;
extern crate pfctl;

use pfctl::PfCtl;
use std::env;

error_chain!{}
quick_main!(run);

fn run() -> Result<()> {
    let mut pf = PfCtl::new().chain_err(|| "Unable to connect to PF")?;

    for anchor_name in env::args().skip(1) {
        pf.try_add_anchor(&anchor_name, pfctl::AnchorKind::Filter)
            .chain_err(|| "Unable to add filter anchor")?;
        pf.try_add_anchor(&anchor_name, pfctl::AnchorKind::Redirect)
            .chain_err(|| "Unable to add redirect anchor")?;

        println!("Added {} as both a redirect and filter anchor", anchor_name);
    }
    Ok(())
}
