extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;
use std::net::{Ipv4Addr, Ipv6Addr};

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing.redirect-rules";

fn make_redirect_rule(to: pfctl::Endpoint, redirect_to: pfctl::Endpoint) -> pfctl::RedirectRule {
    pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .to(to)
        .redirect_to(redirect_to)
        .build()
        .unwrap()
}

fn redirect_rule_ipv4() -> pfctl::RedirectRule {
    make_redirect_rule(
        pfctl::Endpoint(
            pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)),
            pfctl::Port::One(3000, pfctl::PortUnaryModifier::Equal),
        ),
        pfctl::Endpoint(
            pfctl::Ip::from(Ipv4Addr::new(127, 0, 0, 1)),
            pfctl::Port::One(4000, pfctl::PortUnaryModifier::Equal),
        ),
    )
}

fn redirect_rule_ipv6() -> pfctl::RedirectRule {
    make_redirect_rule(
        pfctl::Endpoint(
            pfctl::Ip::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            pfctl::Port::One(3000, pfctl::PortUnaryModifier::Equal),
        ),
        pfctl::Endpoint(
            pfctl::Ip::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            pfctl::Port::One(4000, pfctl::PortUnaryModifier::Equal),
        ),
    )
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
        assert_matches!(pf.add_redirect_rule(ANCHOR_NAME, &rule), Ok(()));
        assert_matches!(
            pfcli::get_nat_rules(ANCHOR_NAME),
            Ok(ref v) if v.len() == 1
        );

        assert_matches!(pf.flush_rules(ANCHOR_NAME, pfctl::RulesetKind::Redirect), Ok(()));
        assert_matches!(
            pfcli::get_nat_rules(ANCHOR_NAME),
            Ok(ref v) if v.len() == 0
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
