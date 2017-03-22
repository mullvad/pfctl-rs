#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
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
