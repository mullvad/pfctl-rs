extern crate pfctl;

#[macro_use]
extern crate error_chain;

use std::net::Ipv4Addr;

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

    let mut rule_builder = pfctl::FilterRuleBuilder::default();
    let rule = rule_builder.action(pfctl::RuleAction::Drop)
        .af(pfctl::AddrFamily::Ipv4)
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &rule).chain_err(|| "Unable to add rule")?;
    let rule2 = rule_builder.from(Ipv4Addr::new(192, 168, 99, 11))
        .action(pfctl::RuleAction::Pass)
        .build()
        .unwrap();
    pf.add_rule(anchor_name, &rule2).chain_err(|| "Unable to add second rule")?;

    Ok(())
}
