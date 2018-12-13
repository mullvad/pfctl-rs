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

use pfctl::{ipnetwork, FilterRuleBuilder, PfCtl, RedirectRuleBuilder};
use std::net::Ipv4Addr;

error_chain! {}
quick_main!(run);

static ANCHOR_NAME: &str = "test.anchor";

fn run() -> Result<()> {
    let mut pf = PfCtl::new().chain_err(|| "Unable to connect to PF")?;
    pf.try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter)
        .chain_err(|| "Unable to add test filter anchor")?;
    pf.try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Redirect)
        .chain_err(|| "Unable to add test redirect anchor")?;

    // Create the firewall rule instances
    let pass_all_rule = FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .build()
        .unwrap();
    let pass_all_ipv4_quick_rule = FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .af(pfctl::AddrFamily::Ipv4)
        .quick(true)
        .build()
        .unwrap();
    let pass_all_ipv6_on_utun0_rule = FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .af(pfctl::AddrFamily::Ipv6)
        .interface("utun0")
        .build()
        .unwrap();

    // Block packets from the entire 10.0.0.0/8 private network.
    let private_net = ipnetwork::Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
    let block_a_private_net_rule = FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
        .from(pfctl::Ip::from(ipnetwork::IpNetwork::V4(private_net)))
        .build()
        .unwrap();

    let redirect_incoming_tcp_from_port_3000_to_4000 = RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .af(pfctl::AddrFamily::Ipv4)
        .proto(pfctl::Proto::Tcp)
        .direction(pfctl::Direction::In)
        .to(pfctl::Port::One(3000, pfctl::PortUnaryModifier::Equal))
        .redirect_to(pfctl::Endpoint::new(
            pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)),
            pfctl::Port::One(4000, pfctl::PortUnaryModifier::Equal),
        ))
        .build()
        .unwrap();

    // Add the rules to the test anchor
    pf.add_rule(ANCHOR_NAME, &pass_all_rule)
        .chain_err(|| "Unable to add rule")?;
    pf.add_rule(ANCHOR_NAME, &pass_all_ipv4_quick_rule)
        .chain_err(|| "Unable to add rule")?;
    pf.add_rule(ANCHOR_NAME, &pass_all_ipv6_on_utun0_rule)
        .chain_err(|| "Unable to add rule")?;
    pf.add_rule(ANCHOR_NAME, &block_a_private_net_rule)
        .chain_err(|| "Unable to add rule")?;
    pf.add_redirect_rule(ANCHOR_NAME, &redirect_incoming_tcp_from_port_3000_to_4000)
        .chain_err(|| "Unable to add redirect rule")?;

    println!("Added a bunch of rules to the {} anchor.", ANCHOR_NAME);
    println!("Run this command to remove them:");
    println!("sudo pfctl -a {} -F all", ANCHOR_NAME);
    Ok(())
}
