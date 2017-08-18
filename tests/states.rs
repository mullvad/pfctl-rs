extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing.states";

fn send_udp_packet(sender: SocketAddr, recepient: SocketAddr) {
    UdpSocket::bind(sender)
        .unwrap()
        .send_to(&[0], recepient)
        .unwrap();
}

fn rule_builder(destination: SocketAddr) -> pfctl::FilterRule {
    pfctl::FilterRuleBuilder::default()
        .action(pfctl::RuleAction::Pass)
        .proto(pfctl::Proto::Udp)
        .to(destination)
        .quick(true)
        .keep_state(pfctl::StatePolicy::Keep)
        .build()
        .unwrap()
}

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

test!(reset_ipv4_states_by_anchor {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let server_addr = SocketAddr::new(ipv4, 1337);
    let sender_addr = SocketAddr::new(ipv4, 1338);

    pf.set_rules(ANCHOR_NAME, &[rule_builder(server_addr)]).unwrap();
    send_udp_packet(sender_addr, server_addr);

    assert_matches!(
        pfcli::get_states(ANCHOR_NAME),
        Ok(ref v) if v == &["ALL udp 127.0.0.1:1338 -> 127.0.0.1:1337       SINGLE:NO_TRAFFIC",
                            "ALL udp 127.0.0.1:1337 <- 127.0.0.1:1338       NO_TRAFFIC:SINGLE"]
    );
    assert_matches!(pf.clear_states(ANCHOR_NAME, pfctl::AnchorKind::Filter), Ok(2));
    assert_matches!(
        pfcli::get_states(ANCHOR_NAME),
        Ok(ref v) if v.len() == 0
    );
});

test!(reset_ipv6_states_by_anchor {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let server_addr = SocketAddr::new(ipv6, 1337);
    let sender_addr = SocketAddr::new(ipv6, 1338);

    pf.set_rules(ANCHOR_NAME, &[rule_builder(server_addr)]).unwrap();
    send_udp_packet(sender_addr, server_addr);

    assert_matches!(
        pfcli::get_states(ANCHOR_NAME),
        Ok(ref v) if v == &["ALL udp ::1[1338] -> ::1[1337]       SINGLE:NO_TRAFFIC",
                            "ALL udp ::1[1337] <- ::1[1338]       NO_TRAFFIC:SINGLE"]
    );
    assert_matches!(pf.clear_states(ANCHOR_NAME, pfctl::AnchorKind::Filter), Ok(2));
    assert_matches!(
        pfcli::get_states(ANCHOR_NAME),
        Ok(ref v) if v.len() == 0
    );
});
