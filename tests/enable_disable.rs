#[macro_use]
extern crate error_chain;
extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
#[allow(dead_code)]
mod helper;
use helper::pfcli;

fn before_each() {}
fn after_each() {}

test!(enable_pf {
    let mut pf = pfctl::PfCtl::new().unwrap();

    assert_matches!(pfcli::disable_firewall(), Ok(()));
    assert_matches!(pf.enable(), Ok(()));
    assert_matches!(pfcli::is_enabled(), Ok(true));
    assert_matches!(pf.enable(), Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)));
    assert_matches!(pf.try_enable(), Ok(()));
    assert_matches!(pfcli::is_enabled(), Ok(true));
});

test!(disable_pf {
    let mut pf = pfctl::PfCtl::new().unwrap();

    assert_matches!(pfcli::enable_firewall(), Ok(()));
    assert_matches!(pf.disable(), Ok(()));
    assert_matches!(pfcli::is_enabled(), Ok(false));
    assert_matches!(pf.disable(), Err(pfctl::Error(pfctl::ErrorKind::StateAlreadyActive, _)));
    assert_matches!(pf.try_disable(), Ok(()));
    assert_matches!(pfcli::is_enabled(), Ok(false));
});
