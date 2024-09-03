#[macro_use]
#[allow(dead_code)]
mod helper;

use crate::helper::pfcli;
use assert_matches::assert_matches;

static ANCHOR_NAME: &str = "pfctl-rs.integration.testing.scrub-rules";

fn before_each() {
    pfctl::PfCtl::new()
        .unwrap()
        .try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Scrub)
        .unwrap();
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::All);
    pfctl::PfCtl::new()
        .unwrap()
        .try_remove_anchor(ANCHOR_NAME, pfctl::AnchorKind::Scrub)
        .unwrap();
}

fn scrub_rule() -> pfctl::ScrubRule {
    pfctl::ScrubRuleBuilder::default()
        .action(pfctl::ScrubRuleAction::Scrub)
        .build()
        .unwrap()
}

fn no_scrub_rule() -> pfctl::ScrubRule {
    pfctl::ScrubRuleBuilder::default()
        .action(pfctl::ScrubRuleAction::NoScrub)
        .build()
        .unwrap()
}

// TODO: transaction tests

test!(flush_scrub_rules {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let test_rules = [scrub_rule(), no_scrub_rule()];
    for rule in test_rules.iter() {
        assert_matches!(pf.add_scrub_rule(ANCHOR_NAME, rule), Ok(()));
        assert_eq!(pfcli::get_rules(ANCHOR_NAME).len(), 1);

        assert_matches!(pf.flush_rules(ANCHOR_NAME, pfctl::RulesetKind::Scrub), Ok(()));
        assert_eq!(
            pfcli::get_rules(ANCHOR_NAME),
            &[] as &[&str]
        );
    }
});

test!(add_scrub_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = scrub_rule();
    assert_matches!(pf.add_scrub_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_eq!(
        pfcli::get_rules(ANCHOR_NAME),
        &["scrub all fragment reassemble"]
    );
});

test!(add_no_scrub_rule {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let rule = no_scrub_rule();
    assert_matches!(pf.add_scrub_rule(ANCHOR_NAME, &rule), Ok(()));
    assert_eq!(
        pfcli::get_rules(ANCHOR_NAME),
        &["no scrub all"]
    );
});
