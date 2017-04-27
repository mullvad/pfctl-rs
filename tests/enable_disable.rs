extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;

fn before_each() {}
fn after_each() {}

test!(enable_pf {
    let mut pf = pfctl::PfCtl::new().unwrap();

    assert_matches!(pfcli::disable_firewall(), Ok(()));
    assert_matches!(pf.enable(), Ok(()));
    assert_matches!(pfcli::is_enabled(), Ok(true));
});

test!(disable_pf {
    let mut pf = pfctl::PfCtl::new().unwrap();

    assert_matches!(pfcli::enable_firewall(), Ok(()));
    assert_matches!(pf.disable(), Ok(()));
    assert_matches!(pfcli::is_enabled(), Ok(false));
});
