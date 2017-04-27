extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing";

fn add_anchor(pf: &mut pfctl::PfCtl) {
    match pf.add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter) {
        Ok(_) => (),
        Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)) => (),
        Err(e) => panic!("Unable to add anchor: {}", e),
    }
}

fn before_each() {
    pfcli::enable_firewall().unwrap();

    let mut pf = pfctl::PfCtl::new().unwrap();
    add_anchor(&mut pf);
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME).unwrap();
}

test!(add_basic_drop_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Drop)
        .proto(pfctl::Proto::Tcp)
        .build()
        .unwrap();

    assert_matches!(pf.add_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_matches!(pfcli::get_rules(ANCHOR_NAME), Ok(ref v) if v == "block drop proto tcp all");
});
