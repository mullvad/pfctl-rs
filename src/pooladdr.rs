// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use conversion::CopyTo;
use ffi;
use rule::Ip;
use std::mem;

use std::ptr;
use std::vec::Vec;

/// Represents a list of IPs used to set up a table of addresses for traffic redirection in PF.
///
/// See pf_rule.rpool.list for more info.
///
/// This class retains the array of `pf_pooladdr` to make sure that pointers used in pf_palist
/// reference the valid memory.
///
/// One should never use `pf_palist` produced by this class past the lifetime expiration of it.
#[derive(Debug)]
pub struct PoolAddrList {
    list: ffi::pfvar::pf_palist,
    pool: Box<[ffi::pfvar::pf_pooladdr]>,
}

impl PoolAddrList {
    pub fn new(ips: &[Ip]) -> Self {
        let mut pool = Self::init_pool(ips);
        Self::link_elements(&mut pool);
        let list = Self::create_palist(&mut pool);

        PoolAddrList {
            list,
            pool: pool.into_boxed_slice(),
        }
    }

    /// Returns a copy of inner pf_palist linked list.
    /// Returned copy should never be used past the lifetime expiration of PoolAddrList.
    pub fn to_palist(&self) -> ffi::pfvar::pf_palist {
        self.list
    }

    fn init_pool(ips: &[Ip]) -> Vec<ffi::pfvar::pf_pooladdr> {
        let mut pool = Vec::with_capacity(ips.len());
        for ip in ips {
            let mut pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pf_pooladdr>() };
            ip.copy_to(&mut pooladdr.addr);
            pool.push(pooladdr);
        }
        pool
    }

    fn link_elements(pool: &mut Vec<ffi::pfvar::pf_pooladdr>) {
        for i in 1..pool.len() {
            let mut elem1 = pool[i - 1];
            let mut elem2 = pool[i];
            elem1.entries.tqe_next = &mut elem2;
            elem2.entries.tqe_prev = &mut elem1.entries.tqe_next;
        }
    }

    fn create_palist(pool: &mut Vec<ffi::pfvar::pf_pooladdr>) -> ffi::pfvar::pf_palist {
        let mut list = unsafe { mem::zeroed::<ffi::pfvar::pf_palist>() };
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
        list
    }
}
