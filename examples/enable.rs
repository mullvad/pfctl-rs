// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use pfctl::PfCtl;

fn main() {
    // Create a handle to the firewall. This opens the file /dev/pf and requires root.
    let mut pf = PfCtl::new().expect("Unable to connect to PF");

    // Try to enable the firewall. Equivalent to the CLI command "pfctl -e".
    match pf.enable() {
        Ok(_) => println!("Enabled PF"),
        Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)) => (),
        err => err.expect("Unable to enable PF"),
    }
}
