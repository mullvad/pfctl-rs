// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ioctl_sys::ioctl;

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
ioctl!(none pf_start with b'D', 1);
// DIOCSTOP
ioctl!(none pf_stop with b'D', 2);
// DIOCADDRULE
ioctl!(readwrite pf_add_rule with b'D', 4; pfvar::pfioc_rule);
// DIOCGETRULES
ioctl!(readwrite pf_get_rules with b'D', 6; pfvar::pfioc_rule);
// DIOCGETRULE
ioctl!(readwrite pf_get_rule with b'D', 7; pfvar::pfioc_rule);
// DIOCCLRSTATES
ioctl!(readwrite pf_clear_states with b'D', 18; pfvar::pfioc_state_kill);
// DIOCGETSTATUS
ioctl!(readwrite pf_get_status with b'D', 21; pfvar::pf_status);
// DIOCGETSTATES
ioctl!(readwrite pf_get_states with b'D', 25; pfvar::pfioc_states);
// DIOCCHANGERULE
ioctl!(readwrite pf_change_rule with b'D', 26; pfvar::pfioc_rule);
// DIOCINSERTRULE
ioctl!(readwrite pf_insert_rule with b'D', 27; pfvar::pfioc_rule);
// DIOCDELETERULE
ioctl!(readwrite pf_delete_rule with b'D', 28; pfvar::pfioc_rule);
// DIOCKILLSTATES
ioctl!(readwrite pf_kill_states with b'D', 41; pfvar::pfioc_state_kill);
// DIOCBEGINADDRS
ioctl!(readwrite pf_begin_addrs with b'D', 51; pfvar::pfioc_pooladdr);
// DIOCADDADDR
ioctl!(readwrite pf_add_addr with b'D', 52; pfvar::pfioc_pooladdr);
// DIOCXBEGIN
ioctl!(readwrite pf_begin_trans with b'D', 81; pfvar::pfioc_trans);
// DIOCXCOMMIT
ioctl!(readwrite pf_commit_trans with b'D', 82; pfvar::pfioc_trans);
// DIOCCLRIFFLAG
ioctl!(readwrite pf_clear_iface_flag with b'D', 90; pfvar::pfioc_iface);
