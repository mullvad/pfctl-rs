// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use pfctl::PfCtl;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pf = PfCtl::new()?;

    for anchor_name in env::args().skip(1) {
        pf.try_add_anchor(&anchor_name, pfctl::AnchorKind::Filter)?;
        pf.try_add_anchor(&anchor_name, pfctl::AnchorKind::Redirect)?;

        println!("Added {} as both a redirect and filter anchor", anchor_name);
    }
    Ok(())
}
