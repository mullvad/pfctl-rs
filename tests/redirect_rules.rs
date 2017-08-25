extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;
use std::net::Ipv4Addr;

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing.rdr-rules";

fn before_each() {
    pfctl::PfCtl::new()
        .unwrap()
        .try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Redirect)
        .unwrap();
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::Nat).unwrap();
}

test!(flush_redirect_rules {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
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
});

test!(add_redirect_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
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
    assert_matches!(pf.add_redirect_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_nat_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["rdr inet from any to 127.0.0.1 port = 3000 -> 127.0.0.1 port 4000"]
    );
});
