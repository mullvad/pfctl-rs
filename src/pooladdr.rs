use conversion::{CopyToFfi, ToFfi};
use ffi;
use rule::Ip;
use std::mem;
use std::net::Ipv4Addr;

use std::ptr;
use std::vec::Vec;

pub struct PoolAddrList {
    list: ffi::pfvar::pf_palist,
    pool: Box<[ffi::pfvar::pf_pooladdr]>,
}

impl PoolAddrList {
    pub fn from_ips(ips: &[Ip]) -> ::Result<Self> {
        let mut list = unsafe { mem::zeroed::<ffi::pfvar::pf_palist>() };
        let mut pool = Vec::new();

        for ip in ips {
            let mut pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pf_pooladdr>() };
            pooladdr.entries.tqe_next = ptr::null_mut();
            ip.copy_to(&mut pooladdr.addr)?;
            pool.push(pooladdr);
        }

        for i in 1..pool.len() {
            let mut elem1 = pool[i - 1];
            let mut elem2 = pool[i];
            elem1.entries.tqe_next = &mut elem2;
            elem2.entries.tqe_prev = &mut elem1.entries.tqe_next;
        }

        if pool.len() > 0 {
            let mut first_elem = pool[0];
            let mut last_elem = pool[pool.len() - 1];

            list.tqh_first = &mut first_elem;
            first_elem.entries.tqe_prev = &mut list.tqh_first;
            last_elem.entries.tqe_next = ptr::null_mut();
            list.tqh_last = &mut last_elem.entries.tqe_next;
        } else {
            list.tqh_first = ptr::null_mut();
            list.tqh_last = &mut list.tqh_first;
        }

        let inst = PoolAddrList {
            list: list,
            pool: pool.into_boxed_slice(),
        };

        Ok(inst)
    }
}

impl ToFfi<ffi::pfvar::pf_palist> for PoolAddrList {
    fn to_ffi(&self) -> ffi::pfvar::pf_palist {
        self.list
    }
}
