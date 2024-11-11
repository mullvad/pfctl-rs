// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use pfctl::PfCtl;
use std::env;

fn main() {
    let mut pf = PfCtl::new().expect("Unable to connect to PF");

    for anchor_name in env::args().skip(1) {
        pf.try_add_anchor(&anchor_name, pfctl::AnchorKind::Filter)
            .expect("Unable to add filter anchor");
        pf.try_add_anchor(&anchor_name, pfctl::AnchorKind::Redirect)
            .expect("Unable to add redirect anchor");
        pf.try_add_anchor(&anchor_name, pfctl::AnchorKind::Scrub)
            .expect("Unable to add scrub anchor");

        println!("Added {anchor_name} as every anchor type");
    }
}
