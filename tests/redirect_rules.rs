#[macro_use]
extern crate error_chain;

#[macro_use]
#[allow(dead_code)]
mod helper;

use crate::helper::pfcli;
use assert_matches::assert_matches;
use std::net::{Ipv4Addr, Ipv6Addr};

static ANCHOR_NAME: &str = "pfctl-rs.integration.testing.redirect-rules";

fn port_mapping_rule(ip: pfctl::Ip) -> pfctl::RedirectRule {
    pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .to(pfctl::Endpoint::new(ip, 3000))
        .redirect_to(pfctl::Endpoint::new(ip, 4000))
        .build()
        .unwrap()
}

fn redirect_rule_ipv4() -> pfctl::RedirectRule {
    port_mapping_rule(pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)))
}

fn redirect_rule_ipv6() -> pfctl::RedirectRule {
    port_mapping_rule(pfctl::Ip::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}

fn before_each() {
    pfctl::PfCtl::new()
        .unwrap()
        .try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Redirect)
        .unwrap();
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::Nat).unwrap();
    pfctl::PfCtl::new()
        .unwrap()
        .try_remove_anchor(ANCHOR_NAME, pfctl::AnchorKind::Redirect)
        .unwrap();
}

test!(flush_redirect_rules {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let test_rules = [redirect_rule_ipv4(), redirect_rule_ipv6()];
    for rule in test_rules.iter() {
        assert_matches!(pf.add_redirect_rule(ANCHOR_NAME, rule), Ok(()));
        assert_matches!(
            pfcli::get_nat_rules(ANCHOR_NAME),
            Ok(ref v) if v.len() == 1
        );

        assert_matches!(pf.flush_rules(ANCHOR_NAME, pfctl::RulesetKind::Redirect), Ok(()));
        assert_matches!(
            pfcli::get_nat_rules(ANCHOR_NAME),
            Ok(ref v) if v.is_empty()
        );
    }
});

test!(add_redirect_rule_ipv4 {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = redirect_rule_ipv4();
    assert_matches!(pf.add_redirect_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_nat_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["rdr inet from any to 127.0.0.1 port = 3000 -> 127.0.0.1 port 4000"]
    );
});

test!(add_redirect_rule_ipv6 {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = redirect_rule_ipv6();
    assert_matches!(pf.add_redirect_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_nat_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["rdr inet6 from any to ::1 port = 3000 -> ::1 port 4000"]
    );
});

test!(add_redirect_rule_on_interface {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .log(pfctl::RuleLog::ExcludeMatchingState)
        .interface("lo0")
        .from(Ipv4Addr::new(1, 2, 3, 4))
        .redirect_to(pfctl::Port::from(1237))
        .build()
        .unwrap();
    assert_matches!(pf.add_redirect_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_nat_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["rdr log on lo0 inet from 1.2.3.4 to any -> any port 1237"]
    );
});
