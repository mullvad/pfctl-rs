#[macro_use]
#[allow(dead_code)]
mod helper;

use crate::helper::pfcli;
use assert_matches::assert_matches;
use pfctl::Port;
use std::net::{Ipv4Addr, Ipv6Addr};

static ANCHOR_NAME: &str = "pfctl-rs.integration.testing.nat-rules";

fn nat_rule(dest: pfctl::Ip, nat_to: pfctl::Ip) -> pfctl::NatRule {
    pfctl::NatRuleBuilder::default()
        .action(pfctl::NatRuleAction::Nat)
        .to(pfctl::Endpoint::new(dest, 1234))
        .nat_to(pfctl::Endpoint::new(
            nat_to,
            Port::Range(32768, 49151, pfctl::PortRangeModifier::Inclusive),
        ))
        .build()
        .unwrap()
}

fn nat_rule_ipv4() -> pfctl::NatRule {
    nat_rule(
        pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)),
        pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 2)),
    )
}

fn nat_rule_ipv6() -> pfctl::NatRule {
    nat_rule(
        pfctl::Ip::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        pfctl::Ip::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)),
    )
}

fn before_each() {
    pfctl::PfCtl::new()
        .unwrap()
        .try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Nat)
        .unwrap();
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::Nat);
    pfctl::PfCtl::new()
        .unwrap()
        .try_remove_anchor(ANCHOR_NAME, pfctl::AnchorKind::Nat)
        .unwrap();
}

test!(add_nat_rule_ipv4 {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = nat_rule_ipv4();
    assert_matches!(pf.add_nat_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_eq!(
        pfcli::get_nat_rules(ANCHOR_NAME),
        &["nat inet from any to 127.0.0.1 port = 1234 -> 127.0.0.2"]
    );
});

test!(add_nat_rule_ipv6 {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = nat_rule_ipv6();
    assert_matches!(pf.add_nat_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_eq!(
        pfcli::get_nat_rules(ANCHOR_NAME),
        &["nat inet6 from any to ::1 port = 1234 -> ::2"]
    );
});
