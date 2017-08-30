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

static ANCHOR_NAME: &str = "test.anchor";

quick_main!(run);

fn run() -> Result<()> {
    let mut pf = pfctl::PfCtl::new().chain_err(|| "Unable to connect to PF")?;
    match pf.enable() {
        Ok(_) => println!("Enabled PF"),
        Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)) => (),
        err => err.chain_err(|| "Unable to enable PF")?,
    }

    pf.try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter)
        .chain_err(|| "Unable to add filter anchor")?;
    pf.try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Redirect)
        .chain_err(|| "Unable to add redirect anchor")?;

    match pf.flush_rules(ANCHOR_NAME, pfctl::RulesetKind::Filter) {
        Ok(_) => println!("Flushed filter rules"),
        err => err.chain_err(|| "Unable to flush filter rules")?,
    }

    match pf.flush_rules(ANCHOR_NAME, pfctl::RulesetKind::Redirect) {
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
    pf.add_rule(ANCHOR_NAME, &pass_all_rule).chain_err(|| "Unable to add rule")?;
    pf.add_rule(ANCHOR_NAME, &pass_all4_quick_rule).chain_err(|| "Unable to add rule")?;
    pf.add_rule(ANCHOR_NAME, &pass_all6_rule).chain_err(|| "Unable to add rule")?;

    let from_net = IpNetwork::from_str("192.168.99.11/24").unwrap();
    let from_net_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .from(pfctl::Ip::from(from_net))
        .build()
        .unwrap();
    pf.add_rule(ANCHOR_NAME, &from_net_rule).chain_err(|| "Unable to add IPv4 net rule")?;

    let to_port_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .to(pfctl::Port::from(9876))
        .build()
        .unwrap();
    pf.add_rule(ANCHOR_NAME, &to_port_rule).chain_err(|| "Unable to add port rule")?;

    let mut rdr_rule_builder = pfctl::RedirectRuleBuilder::default();
    let rdr_rule1 = rdr_rule_builder
        .action(pfctl::RedirectRuleAction::Redirect)
        .af(pfctl::AddrFamily::Ipv4)
        .proto(pfctl::Proto::Tcp)
        .direction(pfctl::Direction::In)
        .to(
            pfctl::Endpoint::new(
                pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)),
                pfctl::Port::One(3000, pfctl::PortUnaryModifier::Equal),
            ),
        )
        .redirect_to(
            pfctl::Endpoint::new(
                pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)),
                pfctl::Port::One(4000, pfctl::PortUnaryModifier::Equal),
            ),
        )
        .build()
        .unwrap();

    pf.add_redirect_rule(ANCHOR_NAME, &rdr_rule1).chain_err(|| "Unable to add rdr rule")?;

    let ipv6 = Ipv6Addr::new(0xbeef, 8, 7, 6, 5, 4, 3, 2);
    let from_ipv6_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .from(ipv6)
        .build()
        .unwrap();
    pf.add_rule(ANCHOR_NAME, &from_ipv6_rule).chain_err(|| "Unable to add IPv6 rule")?;

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
    let mut trans_change = pfctl::AnchorChange::new(ANCHOR_NAME);
    trans_change.set_filter_rules(vec![trans_rule1, trans_rule2]);
    trans_change.set_redirect_rules(vec![trans_rule3]);
    pf.set_rules(vec![trans_change])
        .chain_err(|| "Unable to set rules")?;

    Ok(())
}
