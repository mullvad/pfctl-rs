extern crate pfctl;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate pfctl_test;
use pfctl_test::pfcli;

extern crate oping;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

static ANCHOR_NAME: &'static str = "pfctl-rs.integration.testing.states";

fn send_ping(ip: IpAddr) -> Result<(), oping::PingError> {
    let mut ping = oping::Ping::new();
    ping.set_timeout(1.0)?;
    ping.add_host(format!("{}", ip).as_ref())?;
    ping.send()?;
    Ok(())
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

test!(reset_states_by_anchor {
    let mut pf = pfctl::PfCtl::new().unwrap();

    let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
    let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let icmp_rule = pfctl::FilterRuleBuilder::default()
            .action(pfctl::RuleAction::Pass)
            .proto(pfctl::Proto::Icmp)
            .to(ipv4)
            .quick(true)
            .keep_state(pfctl::StatePolicy::Keep)
            .build()
            .unwrap();
    let icmpv6_rule = pfctl::FilterRuleBuilder::default()
            .action(pfctl::RuleAction::Pass)
            .proto(pfctl::Proto::IcmpV6)
            .to(ipv6)
            .quick(true)
            .keep_state(pfctl::StatePolicy::Keep)
            .build()
            .unwrap();
    pf.set_rules(ANCHOR_NAME, &[icmp_rule, icmpv6_rule]).unwrap();

    send_ping(IpAddr::from(ipv4)).unwrap();
    send_ping(IpAddr::from(ipv6)).unwrap();

    assert_matches!(pf.reset_states(ANCHOR_NAME, pfctl::AnchorKind::Filter), Ok(2));
});
