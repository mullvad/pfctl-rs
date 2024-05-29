#[macro_use]
extern crate error_chain;

#[macro_use]
#[allow(dead_code)]
mod helper;

use crate::helper::pfcli;
use assert_matches::assert_matches;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

static ANCHOR_NAME: &str = "pfctl-rs.integration.testing.states";

fn contains_subset(haystack: &[String], subset: &[&str]) -> bool {
    subset
        .iter()
        .all(|&state| haystack.contains(&state.to_owned()))
}

fn not_contains_subset(haystack: &[String], subset: &[&str]) -> bool {
    subset
        .iter()
        .all(|&state| !haystack.contains(&state.to_owned()))
}

fn send_udp_packet(sender: SocketAddr, recepient: SocketAddr) {
    UdpSocket::bind(sender)
        .unwrap()
        .send_to(&[0], recepient)
        .unwrap();
}

fn rule_builder(destination: SocketAddr) -> pfctl::FilterRule {
    pfctl::FilterRuleBuilder::default()
        .action(pfctl::FilterRuleAction::Pass)
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
    pfctl::PfCtl::new()
        .unwrap()
        .try_remove_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter)
        .unwrap();
}

test!(reset_ipv4_states_by_anchor {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let server_addr = SocketAddr::new(ipv4, 1337);
    let sender_addr = SocketAddr::new(ipv4, 1338);

    pf.add_rule(ANCHOR_NAME, &rule_builder(server_addr)).unwrap();
    send_udp_packet(sender_addr, server_addr);

    let expected_states = [
        "ALL udp 127.0.0.1:1338 -> 127.0.0.1:1337       SINGLE:NO_TRAFFIC",
        "ALL udp 127.0.0.1:1337 <- 127.0.0.1:1338       NO_TRAFFIC:SINGLE"
    ];

    assert_matches!(
        pfcli::get_all_states(),
        Ok(ref v) if contains_subset(v, &expected_states)
    );
    assert_matches!(pf.clear_states(ANCHOR_NAME, pfctl::AnchorKind::Filter), Ok(2));
    assert_matches!(
        pfcli::get_all_states(),
        Ok(ref v) if not_contains_subset(v, &expected_states)
    );
});

test!(reset_ipv6_states_by_anchor {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let server_addr = SocketAddr::new(ipv6, 1337);
    let sender_addr = SocketAddr::new(ipv6, 1338);

    pf.add_rule(ANCHOR_NAME, &rule_builder(server_addr)).unwrap();
    send_udp_packet(sender_addr, server_addr);

    let expected_states = [
        "ALL udp ::1[1338] -> ::1[1337]       SINGLE:NO_TRAFFIC",
        "ALL udp ::1[1337] <- ::1[1338]       NO_TRAFFIC:SINGLE"
    ];

    assert_matches!(
        pfcli::get_all_states(),
        Ok(ref v) if contains_subset(v, &expected_states)
    );
    assert_matches!(pf.clear_states(ANCHOR_NAME, pfctl::AnchorKind::Filter), Ok(2));
    assert_matches!(
        pfcli::get_all_states(),
        Ok(ref v) if not_contains_subset(v, &expected_states)
    );
});
