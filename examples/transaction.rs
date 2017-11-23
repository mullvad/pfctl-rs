// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate pfctl;

#[macro_use]
extern crate error_chain;

use pfctl::PfCtl;

use std::net::Ipv4Addr;

error_chain!{}
quick_main!(run);

static ANCHOR_NAME: &str = "test.anchor";

fn run() -> Result<()> {
    let mut pf = PfCtl::new().chain_err(|| "Unable to connect to PF")?;
    pf.try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter)
        .chain_err(|| "Unable to add test filter anchor")?;
    pf.try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Redirect)
        .chain_err(|| "Unable to add test redirect anchor")?;

    // Create some firewall rules that we want to set in one atomic transaction.
    let trans_rule1 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
        .from(Ipv4Addr::new(192, 168, 234, 1))
        .build()
        .unwrap();
    let trans_rule2 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
        .from(Ipv4Addr::new(192, 168, 234, 2))
        .to(pfctl::Port::from(80))
        .build()
        .unwrap();
    let trans_rule3 = pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .to(pfctl::Port::from(1337))
        .redirect_to(pfctl::Port::from(1338))
        .build()
        .unwrap();

    // Create a transaction changeset and add the rules to it.
    let mut trans_change = pfctl::AnchorChange::new();
    trans_change.set_filter_rules(vec![trans_rule1, trans_rule2]);
    trans_change.set_redirect_rules(vec![trans_rule3]);

    // Execute the transaction. This will OVERWRITE any existing rules under this anchor as it's
    // a set operation, not an add operation.
    pf.set_rules(ANCHOR_NAME, trans_change)
        .chain_err(|| "Unable to set rules")?;

    println!("Added a bunch of rules to the {} anchor.", ANCHOR_NAME);
    println!("Run this command to remove them:");
    println!("sudo pfctl -a {} -f /dev/null", ANCHOR_NAME);
    Ok(())
}
