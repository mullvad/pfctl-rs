// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{AddrFamily, Endpoint};

use Result;
use conversion::{CopyTo, TryCopyTo};
use ffi;
use pooladdr::PoolAddrList;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedirectEndpoint {
    endpoint: Endpoint,
    pool: PoolAddrList,
}

impl RedirectEndpoint {
    pub fn new(endpoint: Endpoint) -> Self {
        RedirectEndpoint {
            endpoint,
            pool: PoolAddrList::new(vec![endpoint.0]),
        }
    }

    pub fn get_af(&self) -> AddrFamily {
        self.endpoint.get_af()
    }
}

impl From<Endpoint> for RedirectEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        RedirectEndpoint::new(endpoint)
    }
}

impl TryCopyTo<ffi::pfvar::pf_pool> for RedirectEndpoint {
    fn try_copy_to(&self, pf_pool: &mut ffi::pfvar::pf_pool) -> Result<()> {
        pf_pool.list = self.pool.to_palist();
        pf_pool.af = self.endpoint.get_af().into();
        self.endpoint.1.try_copy_to(pf_pool)
    }
}

impl CopyTo<ffi::pfvar::pf_pooladdr> for RedirectEndpoint {
    fn copy_to(&self, pf_pooladdr: &mut ffi::pfvar::pf_pooladdr) {
        self.endpoint.0.copy_to(&mut pf_pooladdr.addr);
    }
}
