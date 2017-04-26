extern crate pfctl;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;

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
    assert!(pfcli::enable_firewall().is_ok());
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME).unwrap();
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
    assert_eq!(pfcli::get_rules(ANCHOR_NAME).unwrap(), "block drop proto tcp all");
});
