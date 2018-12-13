#[macro_use]
extern crate error_chain;
extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
#[allow(dead_code)]
mod helper;
use crate::helper::pfcli;

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

    let anchors = pfcli::get_anchors(None).unwrap();
    assert!(anchors.contains(&anchor_name));

    assert_matches!(
        pf.add_anchor(&anchor_name, pfctl::AnchorKind::Filter),
        Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _))
    );
    assert_matches!(pf.try_add_anchor(&anchor_name, pfctl::AnchorKind::Filter), Ok(()));
});

test!(remove_filter_anchor {
    let anchor_name = unique_anchor();
    let mut pf = pfctl::PfCtl::new().unwrap();

    assert_matches!(pf.add_anchor(&anchor_name, pfctl::AnchorKind::Filter), Ok(()));
    assert_matches!(pf.remove_anchor(&anchor_name, pfctl::AnchorKind::Filter), Ok(()));

    let anchors = pfcli::get_anchors(None).unwrap();
    assert!(!anchors.contains(&anchor_name));

    assert_matches!(
        pf.remove_anchor(&anchor_name, pfctl::AnchorKind::Filter),
        Err(pfctl::Error(pfctl::ErrorKind::AnchorDoesNotExist, _))
    );
    assert_matches!(pf.try_remove_anchor(&anchor_name, pfctl::AnchorKind::Filter), Ok(()));
});
