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
        match pf.flush_rules(&anchor_name, pfctl::RulesetKind::Filter) {
            Ok(_) => println!("Flushed filter rules under anchor {}", anchor_name),
            err => err.expect("Unable to flush filter rules"),
        }
        match pf.flush_rules(&anchor_name, pfctl::RulesetKind::Redirect) {
            Ok(_) => println!("Flushed redirect rules under anchor {}", anchor_name),
            err => err.expect("Unable to flush redirect rules"),
        }
    }
}
