extern crate pfctl;

#[macro_use]
extern crate error_chain;
extern crate ipnetwork;

use ipnetwork::IpNetwork;

use std::net::Ipv6Addr;
use std::str::FromStr;

mod errors {
    error_chain! {
        links {
            PfCtlError(super::pfctl::Error, super::pfctl::ErrorKind);
        }
    }
}
use errors::*;

fn main() {
    if let Err(ref e) = run() {
        use std::io::Write;
        let stderr = &mut ::std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "error: {}", e).expect(errmsg);

        for e in e.iter().skip(1) {
            writeln!(stderr, "caused by: {}", e).expect(errmsg);
        }

        // The backtrace is not always generated. Try to run this example
        // with `RUST_BACKTRACE=1`.
        if let Some(backtrace) = e.backtrace() {
            writeln!(stderr, "backtrace: {:?}", backtrace).expect(errmsg);
        }

        ::std::process::exit(1);
    }
}

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
    pf.add_rule(anchor_name, &pass_all_rule).chain_err(|| "Unable to add rule")?;

    let from_net = IpNetwork::from_str("192.168.99.11/24").unwrap();
    let from_net_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .af(pfctl::AddrFamily::Ipv4)
        .from(pfctl::Ip::from(from_net))
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &from_net_rule).chain_err(|| "Unable to add second rule")?;

    let to_port_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .to(pfctl::Port::from(9876))
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &to_port_rule).chain_err(|| "Unable to add third rule")?;

    let ipv6 = Ipv6Addr::new(0xbeef, 8, 7, 6, 5, 4, 3, 2);
    let from_ipv6_rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .af(pfctl::AddrFamily::Ipv6)
        .from(ipv6)
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &from_ipv6_rule).chain_err(|| "Unable to add fourth rule")?;

    Ok(())
}
