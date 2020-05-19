#[macro_use]
extern crate error_chain;

#[macro_use]
#[allow(dead_code)]
mod helper;

use crate::helper::pfcli;
use assert_matches::assert_matches;
use std::net::Ipv4Addr;

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing.filter-rules";

fn before_each() {
    pfctl::PfCtl::new()
        .unwrap()
        .try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter)
        .unwrap();
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::Rules).unwrap();
    pfctl::PfCtl::new()
        .unwrap()
        .try_remove_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter)
        .unwrap();
}

test!(drop_all_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop all"]
    );
});

test!(return_all_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
        .rule_flag(pfctl::RuleFlagSet::new(&[
            pfctl::RuleFlag::Return,
        ]))
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block return all"]
    );
});

test!(drop_by_direction_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
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
        .action(pfctl::FilterRuleAction::Drop)
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
        .action(pfctl::FilterRuleAction::Drop)
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
        .action(pfctl::FilterRuleAction::Drop)
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
        .action(pfctl::FilterRuleAction::Drop)
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
        .action(pfctl::FilterRuleAction::Drop)
        .interface("utun0")
        .build()
        .unwrap();
    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["block drop on utun0 all"]
    );
});

// TODO(andrej):
// currently only transactions support Route. We need to unify code
// in lib.rs for adding single rule and code in transaction.rs.
test!(pass_out_route_rule {
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .direction(pfctl::Direction::Out)
        .route(
            pfctl::Route::RouteTo(
                pfctl::PoolAddr::new("lo0", Ipv4Addr::new(127, 0, 0, 1))
            )
        )
        .proto(pfctl::Proto::Udp)
        .from(Ipv4Addr::new(1, 2, 3, 4))
        .to(pfctl::Port::from(53))
        .build()
        .unwrap();

    let mut change = pfctl::AnchorChange::new();
    change.set_filter_rules(vec![rule]);
    let mut trans = pfctl::Transaction::new();
    trans.add_change(ANCHOR_NAME, change);

    assert_matches!(trans.commit(), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &[
            "pass out route-to (lo0 127.0.0.1) inet proto udp \
            from 1.2.3.4 to any port = 53 no state"
        ]
    );
});

test!(pass_in_reply_to_rule {
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .direction(pfctl::Direction::In)
        .interface("lo1")
        .route(pfctl::Route::reply_to(pfctl::Interface::from("lo9")))
        .from(Ipv4Addr::new(6, 7, 8, 9))
        .build()
        .unwrap();

    let mut change = pfctl::AnchorChange::new();
    change.set_filter_rules(vec![rule]);
    let mut trans = pfctl::Transaction::new();
    trans.add_change(ANCHOR_NAME, change);

    assert_matches!(trans.commit(), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["pass in on lo1 reply-to lo9 inet from 6.7.8.9 to any no state"]
    );
});

test!(pass_in_dup_to_rule {
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .direction(pfctl::Direction::In)
        .interface("lo1")
        .route(pfctl::Route::DupTo(pfctl::PoolAddr::new("lo8", Ipv4Addr::new(1, 2, 3, 4))))
        .from(Ipv4Addr::new(6, 7, 8, 9))
        .build()
        .unwrap();

    let mut change = pfctl::AnchorChange::new();
    change.set_filter_rules(vec![rule]);
    let mut trans = pfctl::Transaction::new();
    trans.add_change(ANCHOR_NAME, change);

    assert_matches!(trans.commit(), Ok(()));
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &[
            "pass in on lo1 dup-to (lo8 1.2.3.4) inet from 6.7.8.9 to any no state"
        ]
    );
});

test!(flush_filter_rules {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
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

test!(all_state_policies {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule1 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .from(Ipv4Addr::new(192, 168, 1, 1))
        .keep_state(pfctl::StatePolicy::None)
        .build()
        .unwrap();
    let rule2 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .from(Ipv4Addr::new(192, 168, 1, 2))
        .proto(pfctl::Proto::Tcp)
        .tcp_flags(
            (
                [pfctl::TcpFlag::Syn],
                [pfctl::TcpFlag::Syn, pfctl::TcpFlag::Ack, pfctl::TcpFlag::Fin, pfctl::TcpFlag::Rst]
            )
        )
        .keep_state(pfctl::StatePolicy::Keep)
        .build()
        .unwrap();
    let rule3 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .from(Ipv4Addr::new(192, 168, 1, 3))
        .proto(pfctl::Proto::Tcp)
        .keep_state(pfctl::StatePolicy::Modulate)
        .build()
        .unwrap();
    let rule4 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .from(Ipv4Addr::new(192, 168, 1, 4))
        .proto(pfctl::Proto::Tcp)
        .keep_state(pfctl::StatePolicy::SynProxy)
        .build()
        .unwrap();
    for rule in [rule1, rule2, rule3, rule4].iter() {
        assert_matches!(pf.add_rule(ANCHOR_NAME, rule), Ok(()));
    }
    assert_matches!(
        pfcli::get_rules(ANCHOR_NAME),
        Ok(ref v) if v == &["pass inet from 192.168.1.1 to any no state",
                            "pass inet proto tcp from 192.168.1.2 to any flags S/FSRA keep state",
                            "pass inet proto tcp from 192.168.1.3 to any flags any modulate state",
                            "pass inet proto tcp from 192.168.1.4 to any flags any synproxy state"]
    );
});

test!(logging {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
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
