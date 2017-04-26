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

    assert!(pfcli::disable_firewall().is_ok());
    assert!(pf.enable().is_ok());
    assert_matches!(pfcli::is_enabled(), Ok(true));
});

test!(disable_pf {
    let mut pf = pfctl::PfCtl::new().unwrap();

    assert!(pfcli::enable_firewall().is_ok());
    assert!(pf.disable().is_ok());
    assert_matches!(pfcli::is_enabled(), Ok(false));
});
