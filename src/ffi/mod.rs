// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use nix::{ioctl_none, ioctl_readwrite};

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub mod pfvar;

pub mod tcp {
    use std::os::raw::c_uint;

    // exports from <netinet/tcp.h>
    pub const TH_FIN: c_uint = 0x01;
    pub const TH_SYN: c_uint = 0x02;
    pub const TH_RST: c_uint = 0x04;
    pub const TH_PSH: c_uint = 0x08;
    pub const TH_ACK: c_uint = 0x10;
    pub const TH_URG: c_uint = 0x20;
    pub const TH_ECE: c_uint = 0x40;
    pub const TH_CWR: c_uint = 0x80;
}

// The definitions of the ioctl calls come from pfvar.h. Look for the comment "ioctl operations"
// The documentation describing the order of calls and accepted parameters can be found at:
// http://man.openbsd.org/pf.4
// DIOCSTART
ioctl_none!(pf_start, b'D', 1);
// DIOCSTOP
ioctl_none!(pf_stop, b'D', 2);
// DIOCADDRULE
ioctl_readwrite!(pf_add_rule, b'D', 4, pfvar::pfioc_rule);
// DIOCGETRULES
ioctl_readwrite!(pf_get_rules, b'D', 6, pfvar::pfioc_rule);
// DIOCGETRULE
ioctl_readwrite!(pf_get_rule, b'D', 7, pfvar::pfioc_rule);
// DIOCCLRSTATES
ioctl_readwrite!(pf_clear_states, b'D', 18, pfvar::pfioc_state_kill);
// DIOCGETSTATUS
ioctl_readwrite!(pf_get_status, b'D', 21, pfvar::pf_status);
// DIOCGETSTATES
ioctl_readwrite!(pf_get_states, b'D', 25, pfvar::pfioc_states);
// DIOCCHANGERULE
ioctl_readwrite!(pf_change_rule, b'D', 26, pfvar::pfioc_rule);
// DIOCINSERTRULE
// Substituted on FreeBSD and OpenBSD by DIOCCHANGERULE with rule.action = PF_CHANGE_REMOVE
ioctl_readwrite!(pf_insert_rule, b'D', 27, pfvar::pfioc_rule);
// DIOCDELETERULE
// Substituted on FreeBSD and OpenBSD by DIOCCHANGERULE with rule.action = PF_CHANGE_REMOVE
#[cfg(any(target_os = "macos"))]
ioctl_readwrite!(pf_delete_rule, b'D', 28, pfvar::pfioc_rule);
// DIOCKILLSTATES
ioctl_readwrite!(pf_kill_states, b'D', 41, pfvar::pfioc_state_kill);
// DIOCBEGINADDRS
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
ioctl_readwrite!(pf_begin_addrs, b'D', 51, pfvar::pfioc_pooladdr);
// DIOCADDADDR
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
ioctl_readwrite!(pf_add_addr, b'D', 52, pfvar::pfioc_pooladdr);
// DIOCGETRULESETS
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
ioctl_readwrite!(pf_get_rulesets, b'D', 58, pfvar::pfioc_ruleset);
// DIOCGETRULESET
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
ioctl_readwrite!(pf_get_ruleset, b'D', 59, pfvar::pfioc_ruleset);
// DIOCXBEGIN
ioctl_readwrite!(pf_begin_trans, b'D', 81, pfvar::pfioc_trans);
// DIOCXCOMMIT
ioctl_readwrite!(pf_commit_trans, b'D', 82, pfvar::pfioc_trans);

// DIOCXEND
// Required by OpenBSD to release the ticket obtained by the DIOCGETRULES command.
#[cfg(any(target_os = "openbsd"))]
ioctl_readwrite!(pf_end_trans, b'D', 100, pfvar::u_int32_t);