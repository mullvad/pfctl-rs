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
        palist_init(&mut list);

        for ip in ips {
            let pooladdr = new_pooladdr(*ip)?;
            pool.push(pooladdr);
        }

        for mut pooladdr in pool.iter_mut() {
            palist_insert_tail(&mut list, &mut pooladdr)?;
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

fn new_pooladdr(addr: Ip) -> ::Result<ffi::pfvar::pf_pooladdr> {
    let mut pf_paddr = unsafe { mem::zeroed::<ffi::pfvar::pf_pooladdr>() };
    addr.copy_to(&mut pf_paddr.addr)?;
    Ok(pf_paddr)
}

fn palist_init(list: &mut ffi::pfvar::pf_palist) {
    list.tqh_first = ptr::null_mut();
    list.tqh_last = &mut list.tqh_first;
}

fn palist_destroy(list: &mut ffi::pfvar::pf_palist) {
    let mut elm = list.tqh_first;
    while !elm.is_null() {
        unsafe {
            let next = (*elm).entries.tqe_next;
            (*elm).entries.tqe_prev = ptr::null_mut();
            (*elm).entries.tqe_next = ptr::null_mut();
            elm = next;
        };
    }

    list.tqh_first = ptr::null_mut();
    list.tqh_last = ptr::null_mut();
}

fn palist_foreach<F>(list: &ffi::pfvar::pf_palist, mut iter: F)
    where F: FnMut(&ffi::pfvar::pf_pooladdr)
{
    let mut elm = list.tqh_first;
    while !elm.is_null() {
        unsafe {
            iter(&*elm);
            elm = (*elm).entries.tqe_next;
        };
    }
}

fn palist_insert_tail(list: &mut ffi::pfvar::pf_palist,
                      pa: &mut ffi::pfvar::pf_pooladdr)
                      -> ::Result<()> {
    ensure!(!list.tqh_last.is_null(),
            ::ErrorKind::InvalidArgument("Pool address list is not initialized."));
    pa.entries.tqe_next = ptr::null_mut();
    pa.entries.tqe_prev = list.tqh_last;
    unsafe {
        *list.tqh_last = pa;
    };
    list.tqh_last = &mut pa.entries.tqe_next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_list() {
        let mut list = unsafe { mem::zeroed::<ffi::pfvar::pf_palist>() };
        palist_init(&mut list);
        assert!(list.tqh_first.is_null());
        assert!(list.tqh_last == &mut list.tqh_first);
    }

    #[test]
    fn insert_elements() {
        let mut addr1 = new_pooladdr(Ip::from(Ipv4Addr::new(127, 0, 0, 1))).unwrap();
        let mut addr2 = new_pooladdr(Ip::from(Ipv4Addr::new(10, 0, 0, 1))).unwrap();
        let mut addr3 = new_pooladdr(Ip::from(Ipv4Addr::new(10, 0, 0, 2))).unwrap();

        let mut list = unsafe { mem::zeroed::<ffi::pfvar::pf_palist>() };

        palist_init(&mut list);
        assert!(palist_insert_tail(&mut list, &mut addr1).is_ok());
        assert!(palist_insert_tail(&mut list, &mut addr2).is_ok());
        assert!(palist_insert_tail(&mut list, &mut addr3).is_ok());

        assert!(list.tqh_first == &mut addr1);
        assert!(list.tqh_last == &mut addr3.entries.tqe_next);

        assert!(addr1.entries.tqe_next == &mut addr2);
        assert!(addr1.entries.tqe_prev == &mut list.tqh_first);

        assert!(addr2.entries.tqe_next == &mut addr3);
        assert!(addr2.entries.tqe_prev == &mut addr1.entries.tqe_next);

        assert!(addr3.entries.tqe_next.is_null());
        assert!(addr3.entries.tqe_prev == &mut addr2.entries.tqe_next);
    }

    #[test]
    fn destroy_list() {
        let mut addr1 = new_pooladdr(Ip::from(Ipv4Addr::new(127, 0, 0, 1))).unwrap();
        let mut addr2 = new_pooladdr(Ip::from(Ipv4Addr::new(10, 0, 0, 1))).unwrap();
        let mut addr3 = new_pooladdr(Ip::from(Ipv4Addr::new(10, 0, 0, 2))).unwrap();
        let mut list = unsafe { mem::zeroed::<ffi::pfvar::pf_palist>() };
        palist_init(&mut list);
        assert!(palist_insert_tail(&mut list, &mut addr1).is_ok());
        assert!(palist_insert_tail(&mut list, &mut addr2).is_ok());
        assert!(palist_insert_tail(&mut list, &mut addr3).is_ok());
        palist_destroy(&mut list);

        assert!(list.tqh_first.is_null());
        assert!(list.tqh_last.is_null());
        assert!(addr1.entries.tqe_prev.is_null());
        assert!(addr1.entries.tqe_next.is_null());
        assert!(addr2.entries.tqe_prev.is_null());
        assert!(addr2.entries.tqe_next.is_null());
        assert!(addr3.entries.tqe_prev.is_null());
        assert!(addr3.entries.tqe_next.is_null());
    }

    #[test]
    fn iterate_list() {
        let mut list = unsafe { mem::zeroed::<ffi::pfvar::pf_palist>() };
        let mut i = 0;
        let mut addrs = [new_pooladdr(Ip::from(Ipv4Addr::new(127, 0, 0, 1))).unwrap(),
                         new_pooladdr(Ip::from(Ipv4Addr::new(10, 0, 0, 1))).unwrap(),
                         new_pooladdr(Ip::from(Ipv4Addr::new(10, 0, 0, 2))).unwrap()];

        palist_init(&mut list);
        for mut addr in addrs.iter_mut() {
            assert!(palist_insert_tail(&mut list, &mut addr).is_ok());
        }

        palist_foreach(&list, |x| {
            assert!(x as *const _ == &addrs[i] as *const _);
            i += 1;
        });

        assert!(i == 3);

        palist_destroy(&mut list);
    }
}
