use core::slice;

use helper::pfcli::get_interface_flags;
use pfctl::InterfaceFlags;
use tun::{AbstractDevice, Configuration};

#[allow(dead_code)]
mod helper;

fn before_each() {}
fn after_each() {}

test!(set_and_reset_interface_flag {
    let temp_tun = tun::Device::new(&Configuration::default()).unwrap();
    let temp_tun_name = temp_tun.tun_name().unwrap();

    let mut pf = pfctl::PfCtl::new().unwrap();

    let interface = pfctl::Interface::from(&temp_tun_name);

    assert_eq!(
        get_interface_flags(&temp_tun_name),
        slice::from_ref(&temp_tun_name),
    );

    pf.set_interface_flag(interface.clone(), InterfaceFlags::Skip).unwrap();

    assert_eq!(
        get_interface_flags(&temp_tun_name),
        &[format!("{temp_tun_name} (skip)")],
        "expected skip flag to be set",
    );

    pf.clear_interface_flag(interface, InterfaceFlags::Skip).unwrap();

    assert_eq!(
        get_interface_flags(&temp_tun_name),
        &[temp_tun_name],
        "expected skip flag to be cleared",
    );
});
