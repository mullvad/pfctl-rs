// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ffi;
use pooladdr::PoolAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Route {
    NoRoute,
    RouteTo(PoolAddr),
}

impl Default for Route {
    fn default() -> Self {
        Route::NoRoute
    }
}

impl<'a> From<&'a Route> for u8 {
    fn from(route: &'a Route) -> u8 {
        match *route {
            Route::NoRoute => ffi::pfvar::PF_NOPFROUTE as u8,
            Route::RouteTo(_) => ffi::pfvar::PF_ROUTETO as u8,
        }
    }
}
