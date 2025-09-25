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

    pf.set_interface_flag(interface.clone(), InterfaceFlags::SKIP).unwrap();

    assert_eq!(
        get_interface_flags(&temp_tun_name),
        &[format!("{temp_tun_name} (skip)")],
        "expected skip flag to be set",
    );

    pf.clear_interface_flag(interface, InterfaceFlags::SKIP).unwrap();

    assert_eq!(
        get_interface_flags(&temp_tun_name),
        &[temp_tun_name],
        "expected skip flag to be cleared",
    );
});

test!(get_all_interfaces_flags {
    let temp_tun = tun::Device::new(&Configuration::default()).unwrap();
    let temp_tun_name = temp_tun.tun_name().unwrap();
    let interface = pfctl::Interface::from(&temp_tun_name);

    let mut pf = pfctl::PfCtl::new().unwrap();
    pf.set_interface_flag(interface.clone(), InterfaceFlags::SKIP).unwrap();

    let iface = pf.get_interfaces(pfctl::Interface::Any)
        .unwrap()
        .into_iter()
        .find(|iface| iface.name == temp_tun_name)
        .unwrap();
    assert!(iface.flags.contains(InterfaceFlags::SKIP), "expected skip flag to be set");
    pf.clear_interface_flag(interface, InterfaceFlags::SKIP).unwrap();
});

test!(get_single_interface_flags {
    let temp_tun = tun::Device::new(&Configuration::default()).unwrap();
    let temp_tun_name = temp_tun.tun_name().unwrap();
    let interface = pfctl::Interface::from(&temp_tun_name);

    let mut pf = pfctl::PfCtl::new().unwrap();
    pf.set_interface_flag(interface.clone(), InterfaceFlags::SKIP).unwrap();

    let ifaces = pf.get_interfaces(pfctl::Interface::from(&temp_tun_name))
        .unwrap();
    assert_eq!(ifaces.len(), 1);

    let iface = ifaces.into_iter().next().unwrap();
    assert!(iface.name == temp_tun_name, "expected tun interface to be returned");
    assert!(iface.flags.contains(InterfaceFlags::SKIP), "expected skip flag to be set");
    pf.clear_interface_flag(interface, InterfaceFlags::SKIP).unwrap();
});
