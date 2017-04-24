extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;

extern crate uuid;
use uuid::Uuid;

fn unique_anchor() -> String {
    format!(
        "pfctl-rs.integration.testing.{}",
        Uuid::new_v4().simple().to_string()
    )
}

fn before_each() {}
fn after_each() {}

test!(add_filter_anchor {
    let anchor_name = unique_anchor();
    let mut pf = pfctl::PfCtl::new().unwrap();

    assert_matches!(pf.add_anchor(&anchor_name, pfctl::AnchorKind::Filter), Ok(()));

    let anchors = pfcli::get_anchors().unwrap();
    assert!(anchors.contains(&anchor_name));
});

test!(remove_filter_anchor {
    let anchor_name = unique_anchor();
    let mut pf = pfctl::PfCtl::new().unwrap();

    assert_matches!(pf.add_anchor(&anchor_name, pfctl::AnchorKind::Filter), Ok(()));
    assert_matches!(pf.remove_anchor(&anchor_name, pfctl::AnchorKind::Filter), Ok(()));

    let anchors = pfcli::get_anchors().unwrap();
    assert!(!anchors.contains(&anchor_name));
});
