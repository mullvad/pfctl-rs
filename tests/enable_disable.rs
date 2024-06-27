#[macro_use]
#[allow(dead_code)]
mod helper;

use crate::helper::pfcli;
use assert_matches::assert_matches;

fn before_each() {}
fn after_each() {}

test!(enable_pf {
    let mut pf = pfctl::PfCtl::new().unwrap();

    pfcli::disable_firewall();
    assert_matches!(pf.enable(), Ok(()));
    assert!(pfcli::is_enabled());
    assert_matches!(pf.enable(), Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)));
    assert_matches!(pf.try_enable(), Ok(()));
    assert!(pfcli::is_enabled());
});

test!(disable_pf {
    let mut pf = pfctl::PfCtl::new().unwrap();

    pfcli::enable_firewall();
    assert_matches!(pf.disable(), Ok(()));
    assert!(!pfcli::is_enabled());
    assert_matches!(pf.disable(), Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)));
    assert_matches!(pf.try_disable(), Ok(()));
    assert!(!pfcli::is_enabled());
});
