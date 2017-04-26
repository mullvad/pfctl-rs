extern crate pfctl;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::PfCli;

fn before_each() {}
fn after_each() {}

test!(enable_pf {
    let pfcli = PfCli;
    let mut pf = pfctl::PfCtl::new().unwrap();

    if pfcli.is_enabled().unwrap() {
        assert!(pfcli.disable_firewall().is_ok());
    }

    assert!(pf.enable().is_ok());
    assert_eq!(pfcli.is_enabled().unwrap(), true);
});

test!(disable_pf {
    let pfcli = PfCli;
    let mut pf = pfctl::PfCtl::new().unwrap();

    if !pfcli.is_enabled().unwrap() {
        assert!(pfcli.enable_firewall().is_ok());
    }

    assert!(pf.disable().is_ok());
    assert_eq!(pfcli.is_enabled().unwrap(), false);
});
