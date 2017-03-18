#[allow(non_camel_case_types)]
pub mod pfvar {
    include!(concat!(env!("OUT_DIR"), "/pfvar.rs"));
}

ioctl!(none pf_start with b'D', 1);
ioctl!(none pf_stop with b'D', 2);
ioctl!(readwrite pf_get_status with b'D', 21; pfvar::pf_status);
