#[macro_use(defer)]
extern crate scopeguard;
extern crate pfctl;

#[macro_use]
extern crate error_chain;

#[macro_use]
mod common;
use common::*;

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing";

fn add_anchor(pf: &mut pfctl::PfCtl) {
    assert!(
        match pf.add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter) {
            Ok(_) => true,
            Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)) => true,
            _ => false,
        }
    );
}

fn before_each() {
    let pfcli = PfCli;
    if !pfcli.is_enabled().unwrap() {
        assert!(pfcli.enable_firewall().is_ok());
    }
}

fn after_each() {
    PfCli.flush_rules(ANCHOR_NAME).unwrap();
}

test!(add_basic_drop_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();

    add_anchor(&mut pf);
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .proto(pfctl::Proto::Tcp)
        .build()
        .unwrap();

    assert!(pf.add_rule(ANCHOR_NAME, &rule).is_ok());
    assert_eq!(PfCli.get_rules(ANCHOR_NAME).unwrap(), "block drop proto tcp all");
});
