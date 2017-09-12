extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;
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
        .action(pfctl::FilterRuleAction::Drop)
        .to(Ipv4Addr::new(127, 0, 0, 1))
        .build()
        .unwrap();
    let rule2 = pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
        .to(Ipv4Addr::new(192, 168, 0, 1))
        .build()
        .unwrap();
    vec![rule1, rule2]
}

fn get_redirect_rules() -> Vec<pfctl::RedirectRule> {
    let rdr_rule1 = pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .to(pfctl::Endpoint::from(pfctl::Port::from(3000)))
        .redirect_to(pfctl::Endpoint::from(pfctl::Port::from(4000)))
        .build()
        .unwrap();
    let rdr_rule2 = pfctl::RedirectRuleBuilder::default()
        .action(pfctl::RedirectRuleAction::Redirect)
        .to(pfctl::Endpoint::from(pfctl::Port::from(5000)))
        .redirect_to(pfctl::Endpoint::from(pfctl::Port::from(6000)))
        .build()
        .unwrap();
    vec![rdr_rule1, rdr_rule2]
}

fn get_marker_filter_rule() -> pfctl::FilterRule {
    pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Drop)
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

fn assert_eq_filter_rules(pf_rules: Vec<String>) {
    assert_eq!(
        pf_rules,
        vec![
            "block drop inet from any to 127.0.0.1",
            "block drop inet from any to 192.168.0.1",
        ]
    );
}

fn assert_eq_redirect_rules(pf_rules: Vec<String>) {
    assert_eq!(
        pf_rules,
        vec![
            "rdr from any to any port = 3000 -> any port 4000",
            "rdr from any to any port = 5000 -> any port 6000",
        ]
    );
}

fn assert_eq_filter_marker_rule(pf_rules: Vec<String>) {
    assert_eq!(pf_rules, vec!["block drop all"]);
}

fn assert_eq_redirect_marker_rule(pf_rules: Vec<String>) {
    assert_eq!(
        pf_rules,
        vec!["rdr from any to any port = 1337 -> any port 1338"]
    );
}

/// Test that replaces filter and redirect rules in single anchor
test!(replace_many_rulesets_in_one_anchor {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let mut change = pfctl::AnchorChange::new(ANCHOR1_NAME);
    change.set_filter_rules(get_filter_rules());
    change.set_redirect_rules(get_redirect_rules());
    assert_matches!(pf.set_rules(vec![change]), Ok(()));
    assert_eq_filter_rules(pfcli::get_rules(ANCHOR1_NAME).unwrap());
    assert_eq_redirect_rules(pfcli::get_nat_rules(ANCHOR1_NAME).unwrap());
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

    assert_matches!(pf.add_rule(ANCHOR1_NAME, &get_marker_filter_rule()), Ok(()));
    assert_eq_filter_marker_rule(pfcli::get_rules(ANCHOR1_NAME).unwrap());

    assert_matches!(pf.add_redirect_rule(ANCHOR2_NAME, &get_marker_redirect_rule()), Ok(()));
    assert_eq_redirect_marker_rule(pfcli::get_nat_rules(ANCHOR2_NAME).unwrap());

    let mut change1 = pfctl::AnchorChange::new(ANCHOR1_NAME);
    change1.set_redirect_rules(get_redirect_rules());

    let mut change2 = pfctl::AnchorChange::new(ANCHOR2_NAME);
    change2.set_filter_rules(get_filter_rules());

    assert_matches!(pf.set_rules(vec![change1, change2]), Ok(()));

    assert_eq_redirect_rules(pfcli::get_nat_rules(ANCHOR1_NAME).unwrap());
    assert_eq_filter_marker_rule(pfcli::get_rules(ANCHOR1_NAME).unwrap());

    assert_eq_filter_rules(pfcli::get_rules(ANCHOR2_NAME).unwrap());
    assert_eq_redirect_marker_rule(pfcli::get_nat_rules(ANCHOR2_NAME).unwrap());
});
