extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;
use std::net::Ipv4Addr;

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing";

fn before_each() {
    let mut pf = pfctl::PfCtl::new().unwrap();
    match pf.add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter) {
        Ok(_) => (),
        Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)) => (),
        Err(e) => panic!("Unable to add anchor: {}", e),
    }
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::Rules).unwrap();
}

test!(drop_all_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop all"]
    );
});

test!(drop_by_direction_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .direction(pfctl::Direction::Out)
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop out all"]
    );
});

test!(drop_quick_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .quick(true)
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop quick all"]
    );
});

test!(drop_by_ip_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .proto(pfctl::Proto::Tcp)
        .from(Ipv4Addr::new(192, 168, 0, 1))
        .to(Ipv4Addr::new(127, 0, 0, 1))
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop inet proto tcp from 192.168.0.1 to 127.0.0.1"]
    );
});

test!(drop_by_port_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .proto(pfctl::Proto::Tcp)
        .from(pfctl::Port::One(3000, pfctl::PortUnaryModifier::Equal))
        .to(pfctl::Port::One(8080, pfctl::PortUnaryModifier::Equal))
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop proto tcp from any port = 3000 to any port = 8080"]
    );
});

test!(drop_by_port_range_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .proto(pfctl::Proto::Tcp)
        .from(pfctl::Port::Range(3000, 4000, pfctl::PortRangeModifier::Inclusive))
        .to(pfctl::Port::Range(5000, 6000, pfctl::PortRangeModifier::Exclusive))
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop proto tcp from any port 3000:4000 to any port 5000 >< 6000"]
    );
});

test!(drop_by_interface_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .interface("utun0")
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop on utun0 all"]
    );
});

test!(flush_filter_rules {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v.len() == 1
    );

    assert_matches!(pf.flush_rules(ANCHOR_NAME, pfctl::RulesetKind::Filter), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v.len() == 0
    );
});

test!(set_filter_rules_with_transaction {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule1 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .from(Ipv4Addr::new(192, 168, 1, 1))
        .build()
        .unwrap();
    let rule2 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .from(Ipv4Addr::new(192, 168, 2, 1))
        .to(pfctl::Port::from(80))
        .build()
        .unwrap();

    assert_matches!(pf.set_rules(ANCHOR_NAME, &[rule1, rule2]), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop inet from 192.168.1.1 to any",
                            "block drop inet from 192.168.2.1 to any port = 80"]
    );
});

test!(all_state_policies {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule1 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .from(Ipv4Addr::new(192, 168, 1, 1))
        .keep_state(pfctl::StatePolicy::None)
        .build()
        .unwrap();
    let rule2 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .from(Ipv4Addr::new(192, 168, 1, 2))
        .proto(pfctl::Proto::Tcp)
        .keep_state(pfctl::StatePolicy::Keep)
        .build()
        .unwrap();
    let rule3 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .from(Ipv4Addr::new(192, 168, 1, 3))
        .proto(pfctl::Proto::Tcp)
        .keep_state(pfctl::StatePolicy::Modulate)
        .build()
        .unwrap();
    let rule4 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .from(Ipv4Addr::new(192, 168, 1, 4))
        .proto(pfctl::Proto::Tcp)
        .keep_state(pfctl::StatePolicy::SynProxy)
        .build()
        .unwrap();

    assert_matches!(pf.set_rules(ANCHOR_NAME, &[rule1, rule2, rule3, rule4]), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["pass inet from 192.168.1.1 to any no state",
                            "pass inet proto tcp from 192.168.1.2 to any flags any keep state",
                            "pass inet proto tcp from 192.168.1.3 to any flags any modulate state",
                            "pass inet proto tcp from 192.168.1.4 to any flags any synproxy state"]
    );
});

test!(logging {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .log(pfctl::RuleLogSet::new(&[
            pfctl::RuleLog::ExcludeMatchingState,
            pfctl::RuleLog::IncludeMatchingState,
            pfctl::RuleLog::SocketOwner,
        ]))
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop log (all, user) all"]
    );
});
