#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub mod pfvar {
    include!(concat!(env!("OUT_DIR"), "/pfvar.rs"));
}

// The definitions of the ioctl calls come from pfvar.h. Look for the comment "ioctl operations"
// DIOCSTART
ioctl!(none pf_start with b'D', 1);
// DIOCSTOP
ioctl!(none pf_stop with b'D', 2);
// DIOCGETSTATUS
ioctl!(readwrite pf_get_status with b'D', 21; pfvar::pf_status);
// DIOCINSERTRULE
ioctl!(readwrite pf_insert_rule with b'D', 27; pfvar::pfioc_rule);
// DIOCCHANGERULE
ioctl!(readwrite pf_change_rule with b'D', 26; pfvar::pfioc_rule);
// DIOCBEGINADDRS
ioctl!(readwrite pf_begin_addrs with b'D', 51; pfvar::pfioc_pooladdr);
