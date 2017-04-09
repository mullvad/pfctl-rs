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
    match pf.add_anchor(anchor_name, pfctl::AnchorKind::Filter) {
        Ok(_) => println!("Added filter anchor \"{}\"", anchor_name),
        Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)) => (),
        err => err.chain_err(|| "Unable to add filter anchor")?,
    }

    match pf.add_anchor(anchor_name, pfctl::AnchorKind::Redirect) {
        Ok(_) => println!("Added redirect anchor \"{}\"", anchor_name),
        Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)) => (),
        err => err.chain_err(|| "Unable to add redirect anchor")?,
    }

    let pass_all_rule =
        pfctl::FilterRuleBuilder::default().action(pfctl::RuleAction::Pass).build().unwrap();
    let pass_all4_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .af(pfctl::AddrFamily::Ipv4)
        .build()
        .unwrap();
    let pass_all6_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .af(pfctl::AddrFamily::Ipv6)
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &pass_all_rule).chain_err(|| "Unable to add rule")?;
    pf.add_rule(anchor_name, &pass_all4_rule).chain_err(|| "Unable to add rule")?;
    pf.add_rule(anchor_name, &pass_all6_rule).chain_err(|| "Unable to add rule")?;

    let from_net = IpNetwork::from_str("192.168.99.11/24").unwrap();
    let from_net_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .from(pfctl::Ip::from(from_net))
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &from_net_rule).chain_err(|| "Unable to add IPv4 net rule")?;

    let to_port_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .to(pfctl::Port::from(9876))
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &to_port_rule).chain_err(|| "Unable to add port rule")?;

    let ipv6 = Ipv6Addr::new(0xbeef, 8, 7, 6, 5, 4, 3, 2);
    let from_ipv6_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .from(ipv6)
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &from_ipv6_rule).chain_err(|| "Unable to add IPv6 rule")?;
    Ok(())
}
