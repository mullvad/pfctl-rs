extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing.states";

fn before_each() {
    pfcli::enable_firewall().unwrap();
    pfctl::PfCtl::new()
        .unwrap()
        .try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter)
        .unwrap();
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::Rules).unwrap();
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::States).unwrap();
}

test!(reset_states_by_anchor {
    let mut pf = pfctl::PfCtl::new().unwrap();

    let ipv4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let udp_rule = pfctl::FilterRuleBuilder::default()
            .action(pfctl::RuleAction::Pass)
            .proto(pfctl::Proto::Udp)
            .to(pfctl::Endpoint(pfctl::Ip::from(ipv4), pfctl::Port::from(1337)))
            .quick(true)
            .keep_state(pfctl::StatePolicy::Keep)
            .build()
            .unwrap();
    let udp6_rule = pfctl::FilterRuleBuilder::default()
            .action(pfctl::RuleAction::Pass)
            .proto(pfctl::Proto::Udp)
            .to(pfctl::Endpoint(pfctl::Ip::from(ipv6), pfctl::Port::from(1337)))
            .quick(true)
            .keep_state(pfctl::StatePolicy::Keep)
            .build()
            .unwrap();
    pf.set_rules(ANCHOR_NAME, &[udp_rule, udp6_rule]).unwrap();

    let udp_socket = UdpSocket::bind(SocketAddr::new(ipv4, 1338)).unwrap();
    let udp6_socket = UdpSocket::bind(SocketAddr::new(ipv6, 1338)).unwrap();
    udp_socket.send_to(&[0], SocketAddr::new(ipv4, 1337)).unwrap();
    udp6_socket.send_to(&[0], SocketAddr::new(ipv6, 1337)).unwrap();

    assert_matches!(pf.reset_states(ANCHOR_NAME, pfctl::AnchorKind::Filter), Ok(4));
});
