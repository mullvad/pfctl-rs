#[macro_use]
#[allow(dead_code)]
mod helper;

use crate::helper::pfcli;
use assert_matches::assert_matches;
use pfctl::{Direction, Proto, State};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

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
    pfcli::enable_firewall();
    pfctl::PfCtl::new()
        .unwrap()
        .try_add_anchor(ANCHOR_NAME, pfctl::AnchorKind::Filter)
        .unwrap();
}

fn after_each() {
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::Rules);
    pfcli::flush_rules(ANCHOR_NAME, pfcli::FlushOptions::States);
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

    assert!(contains_subset(&pfcli::get_all_states(), &expected_states));
    assert_matches!(pf.clear_states(ANCHOR_NAME, pfctl::AnchorKind::Filter), Ok(2));
    assert!(not_contains_subset(&pfcli::get_all_states(), &expected_states));
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

    assert!(contains_subset(&pfcli::get_all_states(), &expected_states));
    assert_matches!(pf.clear_states(ANCHOR_NAME, pfctl::AnchorKind::Filter), Ok(2));
    assert!(not_contains_subset(&pfcli::get_all_states(), &expected_states));
});

#[derive(Debug, PartialEq)]
struct ExpectedState {
    proto: Proto,
    direction: Direction,
    local_address: SocketAddr,
    remote_address: SocketAddr,
}

impl TryFrom<State> for ExpectedState {
    type Error = pfctl::Error;

    fn try_from(state: State) -> Result<Self, Self::Error> {
        Ok(ExpectedState {
            proto: state.proto()?,
            direction: state.direction()?,
            local_address: state.local_address()?,
            remote_address: state.remote_address()?,
        })
    }
}

test!(kill_ipv4_state {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let server_addr = SocketAddr::new(ipv4, 13370);
    let sender_addr = SocketAddr::new(ipv4, 13380);

    pf.add_rule(ANCHOR_NAME, &rule_builder(server_addr)).unwrap();
    send_udp_packet(sender_addr, server_addr);

    std::thread::sleep(Duration::from_millis(1));

    let states = pf.get_states().expect("Could not obtain states");

    let expected_states = [
        // UDP sender_addr -> server_addr
        ExpectedState {
            proto: Proto::Udp,
            direction: Direction::Out,
            local_address: sender_addr,
            remote_address: server_addr,
        },
        // UDP server_addr <- sender_addr
        ExpectedState {
            proto: Proto::Udp,
            direction: Direction::In,
            local_address: server_addr,
            remote_address: sender_addr,
        },
    ];

    for expected_state in &expected_states {
        let Some(state) = states.iter().find(|&state| matches!(ExpectedState::try_from(state.clone()), Ok(v) if v == *expected_state)) else {
            panic!("cannot find state: {expected_state:?}");
        };
        assert_matches!(pf.kill_state(&state), Ok(_));
    }

    let states = pf.get_states()
        .expect("Could not obtain states")
        .into_iter()
        .filter_map(|state| ExpectedState::try_from(state).ok()).collect::<Vec<_>>();

    for expected_state in &expected_states {
        assert!(!states.contains(&expected_state), "state should be removed");
    }
});

test!(kill_ipv6_state {
    let mut pf = pfctl::PfCtl::new().unwrap();
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let server_addr = SocketAddr::new(ipv6, 13371);
    let sender_addr = SocketAddr::new(ipv6, 13381);

    pf.add_rule(ANCHOR_NAME, &rule_builder(server_addr)).unwrap();
    send_udp_packet(sender_addr, server_addr);

    std::thread::sleep(Duration::from_millis(1));

    let states = pf.get_states().expect("Could not obtain states");

    let expected_states = [
        // UDP sender_addr -> server_addr
        ExpectedState {
            proto: Proto::Udp,
            direction: Direction::Out,
            local_address: sender_addr,
            remote_address: server_addr,
        },
        // UDP server_addr <- sender_addr
        ExpectedState {
            proto: Proto::Udp,
            direction: Direction::In,
            local_address: server_addr,
            remote_address: sender_addr,
        },
    ];

    for expected_state in &expected_states {
        let Some(state) = states.iter().find(|&state| matches!(ExpectedState::try_from(state.clone()), Ok(v) if v == *expected_state)) else {
            panic!("cannot find state: {expected_state:?}");
        };
        assert_matches!(pf.kill_state(&state), Ok(_));
    }

    let states = pf.get_states()
        .expect("Could not obtain states")
        .into_iter()
        .filter_map(|state| ExpectedState::try_from(state).ok()).collect::<Vec<_>>();

    for expected_state in &expected_states {
        assert!(!states.contains(&expected_state), "state should be removed");
    }
});
