#[allow(non_camel_case_types)]
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
