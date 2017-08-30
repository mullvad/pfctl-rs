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
extern crate ipnetwork;

use ipnetwork::IpNetwork;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

mod errors {
    error_chain! {
        links {
            PfCtlError(super::pfctl::Error, super::pfctl::ErrorKind);
        }
    }
}
use errors::*;

quick_main!(run);

fn run() -> Result<()> {
    let mut pf = pfctl::PfCtl::new().chain_err(|| "Unable to connect to PF")?;
    match pf.enable() {
        Ok(_) => println!("Enabled PF"),
        Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)) => (),
        err => err.chain_err(|| "Unable to enable PF")?,
    }

    let anchor_name = "test.anchor";

    pf.try_add_anchor(anchor_name, pfctl::AnchorKind::Filter)
        .chain_err(|| "Unable to add filter anchor")?;
    pf.try_add_anchor(anchor_name, pfctl::AnchorKind::Redirect)
        .chain_err(|| "Unable to add redirect anchor")?;

    match pf.flush_rules(anchor_name, pfctl::RulesetKind::Filter) {
        Ok(_) => println!("Flushed filter rules"),
        err => err.chain_err(|| "Unable to flush filter rules")?,
    }

    match pf.flush_rules(anchor_name, pfctl::RulesetKind::Redirect) {
        Ok(_) => println!("Flushed rdr rules"),
        err => err.chain_err(|| "Unable to flush rdr rules")?,
    }

    let pass_all_rule =
        pfctl::FilterRuleBuilder::default().action(pfctl::FilterRuleAction::Pass).build().unwrap();
    let pass_all4_quick_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .af(pfctl::AddrFamily::Ipv4)
        .quick(true)
        .build()
        .unwrap();
    let pass_all6_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .af(pfctl::AddrFamily::Ipv6)
        .interface("utun0")
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &pass_all_rule).chain_err(|| "Unable to add rule")?;
    pf.add_rule(anchor_name, &pass_all4_quick_rule).chain_err(|| "Unable to add rule")?;
    pf.add_rule(anchor_name, &pass_all6_rule).chain_err(|| "Unable to add rule")?;

    let from_net = IpNetwork::from_str("192.168.99.11/24").unwrap();
    let from_net_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .from(pfctl::Ip::from(from_net))
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &from_net_rule).chain_err(|| "Unable to add IPv4 net rule")?;

    let to_port_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .to(pfctl::Port::from(9876))
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &to_port_rule).chain_err(|| "Unable to add port rule")?;

    let ipv6 = Ipv6Addr::new(0xbeef, 8, 7, 6, 5, 4, 3, 2);
    let from_ipv6_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .from(ipv6)
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &from_ipv6_rule).chain_err(|| "Unable to add IPv6 rule")?;

    let trans_rule1 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
        .from(Ipv4Addr::new(192, 168, 1, 1))
        .build()
        .unwrap();
    let trans_rule2 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
        .from(Ipv4Addr::new(192, 168, 2, 1))
        .to(pfctl::Port::from(80))
        .build()
        .unwrap();
    pf.set_rules(anchor_name, &[trans_rule1, trans_rule2]).chain_err(|| "Unable to set rules")?;

    let mut rdr_rule_builder = pfctl::RedirectRuleBuilder::default();
    let rdr_rule1 = rdr_rule_builder
        .action(pfctl::RedirectRuleAction::Redirect)
        .af(pfctl::AddrFamily::Ipv4)
        .proto(pfctl::Proto::Tcp)
        .direction(pfctl::Direction::In)
        .to(
            pfctl::Endpoint(
                pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)),
                pfctl::Port::One(3000, pfctl::PortUnaryModifier::Equal),
            ),
        )
        .redirect_to(
            pfctl::Endpoint(
                pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)),
                pfctl::Port::One(4000, pfctl::PortUnaryModifier::Equal),
            ),
        )
        .build()
        .unwrap();

    pf.add_redirect_rule(anchor_name, &rdr_rule1).chain_err(|| "Unable to add rdr rule")?;

    Ok(())
}
