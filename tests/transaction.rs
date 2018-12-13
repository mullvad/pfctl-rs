#[macro_use]
extern crate error_chain;
extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
#[allow(dead_code)]
mod helper;
use crate::helper::pfcli;

use std::net::Ipv4Addr;

const ANCHOR1_NAME: &'static str = "pfctl-rs.integration.testing.transactions-1";
const ANCHOR2_NAME: &'static str = "pfctl-rs.integration.testing.transactions-2";
const ANCHORS: [&'static str; 2] = [ANCHOR1_NAME, ANCHOR2_NAME];

fn before_each() {
    for anchor_name in ANCHORS.iter() {
        pfctl::PfCtl::new()
            .unwrap()
            .try_add_anchor(anchor_name, pfctl::AnchorKind::Filter)
            .unwrap();
        pfctl::PfCtl::new()
            .unwrap()
            .try_add_anchor(anchor_name, pfctl::AnchorKind::Redirect)
            .unwrap();
    }
}

fn after_each() {
    for anchor_name in ANCHORS.iter() {
        pfcli::flush_rules(anchor_name, pfcli::FlushOptions::Rules).unwrap();
        pfcli::flush_rules(anchor_name, pfcli::FlushOptions::Nat).unwrap();
        pfctl::PfCtl::new()
            .unwrap()
            .try_remove_anchor(anchor_name, pfctl::AnchorKind::Filter)
            .unwrap();
        pfctl::PfCtl::new()
            .unwrap()
            .try_remove_anchor(anchor_name, pfctl::AnchorKind::Redirect)
            .unwrap();
    }
}

fn get_filter_rules() -> Vec<pfctl::FilterRule> {
    let rule1 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .to(Ipv4Addr::new(1, 2, 3, 4))
        .build()
        .unwrap();
    let rule2 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .to(Ipv4Addr::new(9, 8, 7, 6))
        .build()
        .unwrap();
    vec![rule1, rule2]
}

fn get_redirect_rules() -> Vec<pfctl::RedirectRule> {
    let rdr_rule1 = pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .from(Ipv4Addr::new(1, 2, 3, 4))
        .to(pfctl::Port::from(3000))
        .redirect_to(pfctl::Port::from(4000))
        .build()
        .unwrap();
    let rdr_rule2 = pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .from(Ipv4Addr::new(1, 2, 3, 4))
        .to(pfctl::Port::from(5000))
        .redirect_to(pfctl::Port::from(6000))
        .build()
        .unwrap();
    vec![rdr_rule1, rdr_rule2]
}

fn get_marker_filter_rule() -> pfctl::FilterRule {
    pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
        .build()
        .unwrap()
}

fn get_marker_redirect_rule() -> pfctl::RedirectRule {
    pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .to(pfctl::Endpoint::from(pfctl::Port::from(1337)))
        .redirect_to(pfctl::Endpoint::from(pfctl::Port::from(1338)))
        .build()
        .unwrap()
}

fn verify_filter_rules(anchor: &str) {
    assert_matches!(
        pfcli::get_rules(anchor),
        Ok(ref rules) if rules == &vec![
            "pass inet from any to 1.2.3.4 no state",
            "pass inet from any to 9.8.7.6 no state",
        ]
    );
}

fn verify_redirect_rules(anchor: &str) {
    assert_matches!(
        pfcli::get_nat_rules(anchor),
        Ok(ref rules) if rules == &vec![
            "rdr inet from 1.2.3.4 to any port = 3000 -> any port 4000",
            "rdr inet from 1.2.3.4 to any port = 5000 -> any port 6000",
        ]
    );
}

fn verify_filter_marker(anchor: &str) {
    assert_matches!(
        pfcli::get_rules(anchor),
        Ok(ref rules) if rules == &vec!["pass all no state"]
    );
}

fn verify_redirect_marker(anchor: &str) {
    assert_matches!(
        pfcli::get_nat_rules(anchor),
        Ok(ref rules) if rules == &vec!["rdr from any to any port = 1337 -> any port 1338"]
    );
}

/// Test that replaces filter and redirect rules in single anchor
test!(replace_many_rulesets_in_one_anchor {
    let mut pf = pfctl::PfCtl::new().unwrap();

    let mut change = pfctl::AnchorChange::new();
    change.set_filter_rules(get_filter_rules());
    change.set_redirect_rules(get_redirect_rules());

    pf.set_rules(ANCHOR1_NAME, change).unwrap();

    verify_filter_rules(ANCHOR1_NAME);
    verify_redirect_rules(ANCHOR1_NAME);
});

/// Test that adds two different marker rules in two different anchors then runs transaction that
/// replaces the remaining rulesets leaving rulesets with marker rules untouched. (See figure below)
///
///            filter      redirect
/// anchor1:     N            Y
/// anchor2:     Y            N
///
/// Legend:
/// (Y) - rulesets replaced by transaction
/// (N) - rulesets untouched by transaction
test!(replace_one_ruleset_in_many_anchors {
    let mut pf = pfctl::PfCtl::new().unwrap();

    // add marker rules that must remain untouched by transaction
    pf.add_rule(ANCHOR1_NAME, &get_marker_filter_rule()).unwrap();
    pf.add_redirect_rule(ANCHOR2_NAME, &get_marker_redirect_rule()).unwrap();
    verify_filter_marker(ANCHOR1_NAME);
    verify_redirect_marker(ANCHOR2_NAME);

    // create changes for transaction
    let mut change1 = pfctl::AnchorChange::new();
    change1.set_redirect_rules(get_redirect_rules());

    let mut change2 = pfctl::AnchorChange::new();
    change2.set_filter_rules(get_filter_rules());

    // create and run transaction
    let mut trans = pfctl::Transaction::new();
    trans.add_change(ANCHOR1_NAME, change1);
    trans.add_change(ANCHOR2_NAME, change2);
    assert_matches!(trans.commit(), Ok(()));

    // do final rules verification after transaction
    verify_filter_marker(ANCHOR1_NAME);
    verify_redirect_rules(ANCHOR1_NAME);
    verify_filter_rules(ANCHOR2_NAME);
    verify_redirect_marker(ANCHOR2_NAME);
});
